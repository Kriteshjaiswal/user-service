package com.aidocqa.user.service;

import com.aidocqa.user.dto.SessionResponseDto;
import com.aidocqa.user.entity.User;
import com.aidocqa.user.entity.UserSession;
import com.aidocqa.user.kafka.SessionExpiredEvent;
import com.aidocqa.user.kafka.UserEventProducer;
import com.aidocqa.user.repository.UserRepository;
import com.aidocqa.user.repository.UserSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class SessionService {

    private final UserSessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final UserEventProducer eventProducer;
    private final StringRedisTemplate redisTemplate;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String REDIS_SESSION_PREFIX = "session:";

    @Value("${app.session.inactivity-timeout-minutes:10}")
    private int inactivityTimeoutMinutes;

    /**
     * Creates a new user session upon successful login.
     */
    @Transactional
    public UserSession createSession(Long userId, String ipAddress, String userAgent) {
        // Generate secure session ID
        byte[] randomBytes = new byte[32];
        RANDOM.nextBytes(randomBytes);
        String sessionId = "sess_" + Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiresAt = now.plusMinutes(inactivityTimeoutMinutes);

        String deviceType = parseDeviceType(userAgent);

        UserSession session = UserSession.builder()
                .id(sessionId)
                .userId(userId)
                .ipAddress(ipAddress != null ? ipAddress : "127.0.0.1")
                .userAgent(userAgent != null && userAgent.length() > 500 ? userAgent.substring(0, 500) : userAgent)
                .deviceType(deviceType)
                .lastActivityAt(now)
                .expiresAt(expiresAt)
                .isActive(true)
                .build();

        UserSession saved = sessionRepository.save(session);

        // Cache session and user details in Redis with 10-minute TTL
        try {
            if (redisTemplate != null) {
                String redisKey = REDIS_SESSION_PREFIX + sessionId;
                redisTemplate.opsForValue().set(redisKey, String.valueOf(userId), Duration.ofMinutes(inactivityTimeoutMinutes));
                
                userRepository.findById(userId).ifPresent(u -> {
                    if (u.getEmail() != null) {
                        redisTemplate.opsForValue().set(redisKey + ":email", u.getEmail(), Duration.ofMinutes(inactivityTimeoutMinutes));
                    }
                    if (u.getRole() != null) {
                        redisTemplate.opsForValue().set(redisKey + ":role", u.getRole(), Duration.ofMinutes(inactivityTimeoutMinutes));
                    }
                    if (u.getFullName() != null) {
                        redisTemplate.opsForValue().set(redisKey + ":name", u.getFullName(), Duration.ofMinutes(inactivityTimeoutMinutes));
                    }
                });
            }
        } catch (Exception e) {
            log.warn("Redis unavailable, session cached in database only: {}", e.getMessage());
        }

        log.info("Created session [{}] for userId: {} (Expires in {} mins of inactivity)", sessionId, userId, inactivityTimeoutMinutes);
        return saved;
    }

    /**
     * Validates an active session and implements the 10-minute sliding inactivity window.
     */
    @Transactional
    public User validateAndSlideSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("Missing session token");
        }

        UserSession session = sessionRepository.findByIdAndIsActiveTrue(sessionId)
                .orElseThrow(() -> new IllegalArgumentException("Session not found or already logged out"));

        LocalDateTime now = LocalDateTime.now();

        // Enforce 10-Minute Inactivity Window
        if (session.getLastActivityAt().plusMinutes(inactivityTimeoutMinutes).isBefore(now)) {
            session.setActive(false);
            sessionRepository.save(session);

            // Invalidate in Redis
            try {
                if (redisTemplate != null) {
                    redisTemplate.delete(REDIS_SESSION_PREFIX + sessionId);
                }
            } catch (Exception ignored) {}

            // Publish Kafka event
            eventProducer.publishSessionExpired(SessionExpiredEvent.builder()
                    .sessionId(sessionId)
                    .userId(session.getUserId())
                    .reason("INACTIVITY_10_MIN")
                    .build());

            log.info("Session [{}] expired due to {} minutes of inactivity.", sessionId, inactivityTimeoutMinutes);
            throw new IllegalStateException("Your session has expired due to 10 minutes of inactivity. Please log in again.");
        }

        // Slide the window: update lastActivityAt & expiresAt
        session.setLastActivityAt(now);
        session.setExpiresAt(now.plusMinutes(inactivityTimeoutMinutes));
        sessionRepository.save(session);

        // Refresh Redis TTL
        try {
            if (redisTemplate != null) {
                redisTemplate.expire(REDIS_SESSION_PREFIX + sessionId, Duration.ofMinutes(inactivityTimeoutMinutes));
            }
        } catch (Exception ignored) {}

        return userRepository.findById(session.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("User not found for session"));
    }

    /**
     * Retrieves all active sessions for a user.
     */
    public List<SessionResponseDto> getActiveSessions(Long userId, String currentSessionId) {
        List<UserSession> sessions = sessionRepository.findByUserIdAndIsActiveTrueOrderByLastActivityAtDesc(userId);
        return sessions.stream()
                .map(s -> SessionResponseDto.builder()
                        .sessionId(s.getId())
                        .ipAddress(s.getIpAddress())
                        .userAgent(s.getUserAgent())
                        .deviceType(s.getDeviceType())
                        .createdAt(s.getCreatedAt())
                        .lastActivityAt(s.getLastActivityAt())
                        .expiresAt(s.getExpiresAt())
                        .active(s.isActive())
                        .current(s.getId().equals(currentSessionId))
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Revokes a specific session.
     */
    @Transactional
    public void revokeSession(String sessionId, Long requestingUserId) {
        UserSession session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new IllegalArgumentException("Session not found"));

        if (!session.getUserId().equals(requestingUserId)) {
            throw new IllegalArgumentException("Unauthorized to revoke this session");
        }

        session.setActive(false);
        sessionRepository.save(session);

        try {
            if (redisTemplate != null) {
                redisTemplate.delete(REDIS_SESSION_PREFIX + sessionId);
            }
        } catch (Exception ignored) {}

        eventProducer.publishSessionExpired(SessionExpiredEvent.builder()
                .sessionId(sessionId)
                .userId(requestingUserId)
                .reason("MANUAL_REVOCATION")
                .build());

        log.info("Session [{}] revoked by user {}.", sessionId, requestingUserId);
    }

    /**
     * Revokes all active sessions for a user except the current one.
     */
    @Transactional
    public void revokeOtherSessions(Long userId, String currentSessionId) {
        sessionRepository.deactivateOtherSessions(userId, currentSessionId);
        log.info("Revoked all other sessions for user {} except current session [{}].", userId, currentSessionId);
    }

    /**
     * Scheduled cleanup of inactive expired sessions running every 5 minutes.
     */
    @Scheduled(fixedRate = 300000)
    @Transactional
    public void cleanExpiredSessions() {
        int deactivated = sessionRepository.deactivateExpiredSessions(LocalDateTime.now());
        if (deactivated > 0) {
            log.info("Cleaned up {} expired sessions in database.", deactivated);
        }
    }

    private String parseDeviceType(String userAgent) {
        if (userAgent == null) return "Desktop";
        String ua = userAgent.toLowerCase();
        if (ua.contains("mobile") || ua.contains("android") || ua.contains("iphone")) {
            return "Mobile Device";
        } else if (ua.contains("ipad") || ua.contains("tablet")) {
            return "Tablet";
        } else if (ua.contains("macintosh") || ua.contains("mac os")) {
            return "Mac Desktop";
        } else if (ua.contains("windows")) {
            return "Windows PC";
        } else if (ua.contains("linux")) {
            return "Linux Desktop";
        }
        return "Web Client";
    }
}
