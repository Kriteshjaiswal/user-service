package com.aidocqa.user.service;

import com.aidocqa.user.dto.SessionResponseDto;
import com.aidocqa.user.dto.UserDetailResponseDto;
import com.aidocqa.user.dto.UserResponseDto;
import com.aidocqa.user.entity.User;
import com.aidocqa.user.entity.UserAuditLog;
import com.aidocqa.user.kafka.UserDeletedEvent;
import com.aidocqa.user.kafka.UserEventProducer;
import com.aidocqa.user.repository.UserAuditLogRepository;
import com.aidocqa.user.repository.UserRepository;
import com.aidocqa.user.repository.UserSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;
    private final UserAuditLogRepository auditLogRepository;
    private final SessionService sessionService;
    private final UserEventProducer eventProducer;
    private final AuthService authService;

    public UserResponseDto getCurrentUserProfile(User user, String currentSessionId) {
        List<SessionResponseDto> sessions = sessionService.getActiveSessions(user.getId(), currentSessionId);
        return authService.mapToUserResponse(user, sessions.size(), user.getUpdatedAt());
    }

    @Transactional
    public UserResponseDto updateProfile(Long userId, String fullName, String avatarUrl) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (fullName != null && !fullName.isBlank()) {
            user.setFullName(fullName.trim());
        }
        if (avatarUrl != null) {
            user.setAvatarUrl(avatarUrl.trim());
        }

        User updated = userRepository.save(user);
        return authService.mapToUserResponse(updated, 1, null);
    }

    public Page<UserResponseDto> getAllUsers(String query, String role, String provider, String status, Pageable pageable) {
        Page<User> usersPage = userRepository.searchUsers(query, role, provider, status, pageable);
        return usersPage.map(u -> {
            int activeSessionsCount = sessionRepository.findByUserIdAndIsActiveTrueOrderByLastActivityAtDesc(u.getId()).size();
            return authService.mapToUserResponse(u, activeSessionsCount, u.getUpdatedAt());
        });
    }

    public UserDetailResponseDto getUserDetail(Long targetUserId, String currentSessionId) {
        User user = userRepository.findById(targetUserId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + targetUserId));

        List<SessionResponseDto> activeSessions = sessionService.getActiveSessions(user.getId(), currentSessionId);
        List<UserAuditLog> auditLogs = auditLogRepository.findTop20ByUserIdOrderByTimestampDesc(user.getId());

        List<UserDetailResponseDto.AuditLogResponseDto> logDtos = auditLogs.stream()
                .map(l -> UserDetailResponseDto.AuditLogResponseDto.builder()
                        .id(l.getId())
                        .action(l.getAction())
                        .ipAddress(l.getIpAddress())
                        .userAgent(l.getUserAgent())
                        .details(l.getDetails())
                        .timestamp(l.getTimestamp() != null ? l.getTimestamp().toString() : "")
                        .build())
                .collect(Collectors.toList());

        return UserDetailResponseDto.builder()
                .user(authService.mapToUserResponse(user, activeSessions.size(), user.getUpdatedAt()))
                .activeSessions(activeSessions)
                .recentAuditLogs(logDtos)
                .build();
    }

    @Transactional
    public UserResponseDto updateUserStatus(Long targetUserId, String role, String accountStatus) {
        User user = userRepository.findById(targetUserId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + targetUserId));

        if (role != null && !role.isBlank()) {
            user.setRole(role.toUpperCase());
        }
        if (accountStatus != null && !accountStatus.isBlank()) {
            user.setAccountStatus(accountStatus.toUpperCase());
            if ("SUSPENDED".equalsIgnoreCase(accountStatus)) {
                // Terminate all user sessions if suspended
                sessionRepository.deactivateAllUserSessions(user.getId());
            }
        }

        User saved = userRepository.save(user);
        return authService.mapToUserResponse(saved, 0, null);
    }

    @Transactional
    public void deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + userId));

        // Terminate all sessions
        sessionRepository.deactivateAllUserSessions(userId);

        // Delete user record
        userRepository.delete(user);

        // Publish Kafka UserDeletedEvent for downstream cleanup
        eventProducer.publishUserDeleted(UserDeletedEvent.builder()
                .userId(userId)
                .email(user.getEmail())
                .build());

        log.info("User {} (ID: {}) deleted and Kafka event dispatched.", user.getEmail(), userId);
    }
}
