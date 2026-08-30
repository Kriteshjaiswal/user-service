package com.aidocqa.user.service;

import com.aidocqa.user.dto.*;
import com.aidocqa.user.entity.User;
import com.aidocqa.user.entity.UserAuditLog;
import com.aidocqa.user.entity.UserSession;
import com.aidocqa.user.kafka.UserCreatedEvent;
import com.aidocqa.user.kafka.UserEventProducer;
import com.aidocqa.user.repository.UserAuditLogRepository;
import com.aidocqa.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserAuditLogRepository auditLogRepository;
    private final EmailOtpService emailOtpService;
    private final SessionService sessionService;
    private final OAuthService oauthService;
    private final UserEventProducer eventProducer;
    private final PasswordEncoder passwordEncoder;
    private final com.aidocqa.user.security.JwtService jwtService;

    /**
     * User registration with 4-digit OTP email verification.
     */
    @Transactional
    public AuthResponseDto register(RegisterRequestDto request, String ipAddress, String userAgent) {
        String normalizedEmail = request.getEmail().trim().toLowerCase();

        Optional<User> existingUserOpt = userRepository.findByEmail(normalizedEmail);
        if (existingUserOpt.isPresent() && existingUserOpt.get().isEmailVerified()) {
            throw new IllegalArgumentException("An account with this email address already exists. Please log in.");
        }

        // Hash password
        String passwordHash = passwordEncoder.encode(request.getPassword());

        // Store pending registration in temporary storage until 4-digit OTP is successfully verified (ZERO DB PERSISTENCE)
        emailOtpService.createAndSendRegistrationVerification(normalizedEmail, request.getFullName().trim(), passwordHash);

        return AuthResponseDto.builder()
                .requiresOtpVerification(true)
                .message("Account verification pending. Please enter the 4-digit OTP sent to " + normalizedEmail)
                .user(UserResponseDto.builder()
                        .fullName(request.getFullName().trim())
                        .email(normalizedEmail)
                        .role("ROLE_USER")
                        .provider("LOCAL")
                        .emailVerified(false)
                        .accountStatus("PENDING_VERIFICATION")
                        .build())
                .build();
    }

    /**
     * Session-based user login with 10-minute inactivity sliding window.
     */
    @Transactional
    public AuthResponseDto login(LoginRequestDto request, String ipAddress, String userAgent) {
        String normalizedEmail = request.getEmail().trim().toLowerCase();

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password. Please verify your credentials."));

        if (!user.hasPassword()) {
            throw new IllegalArgumentException("This account was created via " + user.getProvider() + " OAuth. Please log in with " + user.getProvider() + " or set a password.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            auditLogRepository.save(UserAuditLog.builder()
                    .userId(user.getId())
                    .action("LOGIN_FAILED")
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .details("Invalid password attempt")
                    .build());
            throw new IllegalArgumentException("Invalid email or password. Please verify your credentials.");
        }

        if ("SUSPENDED".equalsIgnoreCase(user.getAccountStatus())) {
            throw new IllegalStateException("Your account has been suspended. Please contact support.");
        }

        // If email not verified, prompt OTP verification
        if (!user.isEmailVerified()) {
            emailOtpService.createAndSendVerification(user, "REGISTRATION");
            return AuthResponseDto.builder()
                    .requiresOtpVerification(true)
                    .message("Email verification pending. We have sent a fresh 4-digit OTP to your email.")
                    .user(mapToUserResponse(user, 0, null))
                    .build();
        }

        // Create session
        UserSession session = sessionService.createSession(user.getId(), ipAddress, userAgent);

        auditLogRepository.save(UserAuditLog.builder()
                .userId(user.getId())
                .action("LOGIN_SUCCESS")
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .details("Session login successful")
                .build());

        String jwtToken = jwtService.generateToken(user, session.getId());

        return AuthResponseDto.builder()
                .sessionId(session.getId())
                .token(jwtToken)
                .requiresOtpVerification(false)
                .message("Login successful")
                .user(mapToUserResponse(user, 1, session.getLastActivityAt()))
                .build();
    }

    /**
     * Verifies 4-digit OTP and automatically logs the user in.
     */
    @Transactional
    public AuthResponseDto verifyOtpAndLogin(VerifyOtpRequestDto request, String ipAddress, String userAgent) {
        User verifiedUser = emailOtpService.verifyOtp(request.getEmail().trim().toLowerCase(), request.getOtpCode().trim());
        UserSession session = sessionService.createSession(verifiedUser.getId(), ipAddress, userAgent);
        String jwtToken = jwtService.generateToken(verifiedUser, session.getId());

        return AuthResponseDto.builder()
                .sessionId(session.getId())
                .token(jwtToken)
                .requiresOtpVerification(false)
                .message("Email verified successfully. Welcome to DocuMind!")
                .user(mapToUserResponse(verifiedUser, 1, session.getLastActivityAt()))
                .build();
    }

    /**
     * Verifies magic link token and automatically logs the user in.
     */
    @Transactional
    public AuthResponseDto verifyMagicLinkAndLogin(String token, String ipAddress, String userAgent) {
        User verifiedUser = emailOtpService.verifyMagicLink(token);
        UserSession session = sessionService.createSession(verifiedUser.getId(), ipAddress, userAgent);
        String jwtToken = jwtService.generateToken(verifiedUser, session.getId());

        return AuthResponseDto.builder()
                .sessionId(session.getId())
                .token(jwtToken)
                .requiresOtpVerification(false)
                .message("Email verified successfully via magic link.")
                .user(mapToUserResponse(verifiedUser, 1, session.getLastActivityAt()))
                .build();
    }

    /**
     * Resends 4-digit OTP.
     */
    @Transactional
    public void resendOtp(String email) {
        emailOtpService.resendRegistrationOtp(email.trim().toLowerCase());
    }

    /**
     * Handles Google / GitHub OAuth callback, auto-verifies, and creates session.
     */
    @Transactional
    public AuthResponseDto oauthLogin(String provider, OAuthLoginRequestDto request, String ipAddress, String userAgent) {
        OAuthService.OAuthResult result = oauthService.processOAuthLogin(provider, request.getCode(), request.getRedirectUri(), ipAddress);
        User user = result.user();
        UserSession session = sessionService.createSession(user.getId(), ipAddress, userAgent);
        String jwtToken = jwtService.generateToken(user, session.getId());

        return AuthResponseDto.builder()
                .sessionId(session.getId())
                .token(jwtToken)
                .isNewUser(result.isNewUser())
                .requiresOtpVerification(false)
                .message(provider.toUpperCase() + " authentication successful")
                .user(mapToUserResponse(user, 1, session.getLastActivityAt()))
                .build();
    }

    /**
     * Allows OAuth users or users without local password to set a password.
     */
    @Transactional
    public UserResponseDto setPassword(Long userId, SetPasswordRequestDto request, String ipAddress) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        User updated = userRepository.save(user);

        auditLogRepository.save(UserAuditLog.builder()
                .userId(user.getId())
                .action("PASSWORD_SET")
                .ipAddress(ipAddress)
                .details("Set local account password")
                .build());

        log.info("User {} set a local password.", user.getEmail());
        return mapToUserResponse(updated, 1, null);
    }

    /**
     * Logs out the user from current session.
     */
    @Transactional
    public void logout(String sessionId, Long userId) {
        if (sessionId != null && !sessionId.isBlank()) {
            sessionService.revokeSession(sessionId, userId);
        }
    }

    public UserResponseDto mapToUserResponse(User user, int activeSessionsCount, java.time.LocalDateTime lastActiveAt) {
        return UserResponseDto.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .role(user.getRole())
                .provider(user.getProvider())
                .avatarUrl(user.getAvatarUrl())
                .emailVerified(user.isEmailVerified())
                .hasPassword(user.hasPassword())
                .accountStatus(user.getAccountStatus())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .activeSessionsCount(activeSessionsCount)
                .lastActiveAt(lastActiveAt)
                .build();
    }
}
