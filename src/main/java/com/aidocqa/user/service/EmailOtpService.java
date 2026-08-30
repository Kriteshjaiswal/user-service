package com.aidocqa.user.service;

import com.aidocqa.user.entity.User;
import com.aidocqa.user.entity.UserAuditLog;
import com.aidocqa.user.entity.UserVerification;
import com.aidocqa.user.kafka.EmailOtpEvent;
import com.aidocqa.user.kafka.UserEventProducer;
import com.aidocqa.user.kafka.UserVerifiedEvent;
import com.aidocqa.user.repository.UserAuditLogRepository;
import com.aidocqa.user.repository.UserRepository;
import com.aidocqa.user.repository.UserVerificationRepository;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailOtpService {

    private final UserRepository userRepository;
    private final UserVerificationRepository verificationRepository;
    private final UserAuditLogRepository auditLogRepository;
    private final UserEventProducer eventProducer;
    private final JavaMailSender mailSender;

    private static final SecureRandom RANDOM = new SecureRandom();

    @Value("${app.otp.expiration-minutes:10}")
    private int otpExpirationMinutes;

    @Value("${app.frontend-url:http://localhost:5173}")
    private String frontendUrl;

    @Value("${spring.mail.username:kriteshjaiswal0007@gmail.com}")
    private String mailUsername;

    // Temporary storage for pending registrations (Zero DB persistence before successful verification)
    private final java.util.concurrent.ConcurrentHashMap<String, PendingRegistration> pendingRegistrations = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<String, String> tokenToEmailMap = new java.util.concurrent.ConcurrentHashMap<>();

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class PendingRegistration {
        private String email;
        private String fullName;
        private String passwordHash;
        private String otpCode;
        private String magicToken;
        private LocalDateTime expiresAt;
        private int attempts;
    }

    /**
     * Stores pending registration in-memory with 10-min expiration (NO DB INSERT),
     * and sends 4-digit OTP and 1-click magic link.
     */
    public void createAndSendRegistrationVerification(String email, String fullName, String passwordHash) {
        String normalizedEmail = email.trim().toLowerCase();
        int codeInt = 1000 + RANDOM.nextInt(9000);
        String otpCode = String.valueOf(codeInt);
        String magicToken = UUID.randomUUID().toString().replace("-", "");
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(otpExpirationMinutes);

        PendingRegistration pending = PendingRegistration.builder()
                .email(normalizedEmail)
                .fullName(fullName)
                .passwordHash(passwordHash)
                .otpCode(otpCode)
                .magicToken(magicToken)
                .expiresAt(expiresAt)
                .attempts(0)
                .build();

        pendingRegistrations.put(normalizedEmail, pending);
        tokenToEmailMap.put(magicToken, normalizedEmail);

        String magicLinkUrl = String.format("%s/verify-email?token=%s", frontendUrl, magicToken);

        sendHtmlVerificationEmail(normalizedEmail, fullName, otpCode, magicLinkUrl);
        log.info("Generated 4-digit OTP [{}] for pending registration: {} (Expires in {} mins)", otpCode, normalizedEmail, otpExpirationMinutes);
    }

    /**
     * Generates a 4-digit numeric OTP for an existing unverified user.
     */
    @Transactional
    public UserVerification createAndSendVerification(User user, String type) {
        int codeInt = 1000 + RANDOM.nextInt(9000);
        String otpCode = String.valueOf(codeInt);
        String magicToken = UUID.randomUUID().toString().replace("-", "");
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(otpExpirationMinutes);

        UserVerification verification = UserVerification.builder()
                .userId(user.getId())
                .otpCode(otpCode)
                .token(magicToken)
                .type(type != null ? type : "REGISTRATION")
                .expiresAt(expiresAt)
                .isUsed(false)
                .attempts(0)
                .build();

        UserVerification saved = verificationRepository.save(verification);
        String magicLinkUrl = String.format("%s/verify-email?token=%s", frontendUrl, magicToken);
        sendHtmlVerificationEmail(user.getEmail(), user.getFullName(), otpCode, magicLinkUrl);

        log.info("Generated 4-digit OTP [{}] for user: {} (Expires in {} mins)", otpCode, user.getEmail(), otpExpirationMinutes);
        return saved;
    }

    /**
     * Validates 4-digit OTP. If from pending registration, SAVES user to database ONLY NOW upon success.
     */
    @Transactional
    public User verifyOtp(String email, String otpCode) {
        String normalizedEmail = email != null ? email.trim().toLowerCase() : "";
        String normalizedCode = otpCode != null ? otpCode.trim() : "";

        // 1. Check in-memory pending registration
        PendingRegistration pending = pendingRegistrations.get(normalizedEmail);
        if (pending != null) {
            if (pending.getExpiresAt().isBefore(LocalDateTime.now())) {
                pendingRegistrations.remove(normalizedEmail);
                tokenToEmailMap.remove(pending.getMagicToken());
                throw new IllegalArgumentException("The verification code has expired. Please register again.");
            }

            pending.setAttempts(pending.getAttempts() + 1);
            if (pending.getAttempts() > 5) {
                pendingRegistrations.remove(normalizedEmail);
                tokenToEmailMap.remove(pending.getMagicToken());
                throw new IllegalArgumentException("Too many invalid attempts. Please register again.");
            }

            if (!pending.getOtpCode().equals(normalizedCode)) {
                throw new IllegalArgumentException("Invalid 4-digit OTP. Please check your email and try again.");
            }

            // OTP verified successfully! NOW create and save User in MySQL database
            User newUser = User.builder()
                    .fullName(pending.getFullName())
                    .email(pending.getEmail())
                    .passwordHash(pending.getPasswordHash())
                    .role("ROLE_USER")
                    .provider("LOCAL")
                    .isEmailVerified(true)
                    .accountStatus("ACTIVE")
                    .build();

            User savedUser = userRepository.save(newUser);

            pendingRegistrations.remove(normalizedEmail);
            tokenToEmailMap.remove(pending.getMagicToken());

            try {
                auditLogRepository.save(UserAuditLog.builder()
                        .userId(savedUser.getId())
                        .action("OTP_VERIFIED")
                        .details("4-digit OTP verified; user account created and activated")
                        .build());
            } catch (Exception e) {
                log.warn("Audit log save skipped: {}", e.getMessage());
            }

            log.info("User {} successfully registered and verified with OTP code.", savedUser.getEmail());
            return savedUser;
        }

        // 2. Check existing unverified user in database (backward compatibility)
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new IllegalArgumentException("No pending verification request found for email: " + email));

        UserVerification verification = verificationRepository
                .findTopByUserIdAndTypeAndIsUsedFalseOrderByCreatedAtDesc(user.getId(), "REGISTRATION")
                .or(() -> verificationRepository.findTopByUserIdAndIsUsedFalseOrderByCreatedAtDesc(user.getId()))
                .orElseThrow(() -> new IllegalArgumentException("No pending verification request found. Please request a new code."));

        if (verification.isExpired()) {
            throw new IllegalArgumentException("The verification code has expired. Please request a new one.");
        }

        verification.setAttempts(verification.getAttempts() + 1);

        if (verification.getAttempts() > 5) {
            verification.setUsed(true);
            verificationRepository.save(verification);
            throw new IllegalArgumentException("Too many invalid attempts. Please request a new verification code.");
        }

        if (!verification.getOtpCode().equals(normalizedCode)) {
            verificationRepository.save(verification);
            throw new IllegalArgumentException("Invalid 4-digit OTP. Please check your email and try again.");
        }

        verification.setUsed(true);
        verificationRepository.save(verification);

        user.setEmailVerified(true);
        user.setAccountStatus("ACTIVE");
        User updatedUser = userRepository.save(user);

        log.info("User {} successfully verified with OTP code.", user.getEmail());
        return updatedUser;
    }

    /**
     * Validates Magic Verification Link Token.
     */
    @Transactional
    public User verifyMagicLink(String token) {
        String normalizedEmail = tokenToEmailMap.get(token);
        if (normalizedEmail != null) {
            PendingRegistration pending = pendingRegistrations.get(normalizedEmail);
            if (pending != null) {
                if (pending.getExpiresAt().isBefore(LocalDateTime.now())) {
                    pendingRegistrations.remove(normalizedEmail);
                    tokenToEmailMap.remove(token);
                    throw new IllegalArgumentException("This verification link has expired. Please register again.");
                }

                // Create and save User in MySQL database
                User newUser = User.builder()
                        .fullName(pending.getFullName())
                        .email(pending.getEmail())
                        .passwordHash(pending.getPasswordHash())
                        .role("ROLE_USER")
                        .provider("LOCAL")
                        .isEmailVerified(true)
                        .accountStatus("ACTIVE")
                        .build();

                User savedUser = userRepository.save(newUser);
                pendingRegistrations.remove(normalizedEmail);
                tokenToEmailMap.remove(token);

                log.info("User {} successfully registered and verified via magic link.", savedUser.getEmail());
                return savedUser;
            }
        }

        UserVerification verification = verificationRepository.findByTokenAndIsUsedFalse(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or already used verification link."));

        if (verification.isExpired()) {
            throw new IllegalArgumentException("This verification link has expired. Please request a new one.");
        }

        User user = userRepository.findById(verification.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("User not found."));

        verification.setUsed(true);
        verificationRepository.save(verification);

        user.setEmailVerified(true);
        user.setAccountStatus("ACTIVE");
        return userRepository.save(user);
    }

    /**
     * Resends OTP code for pending registration or existing user.
     */
    public void resendRegistrationOtp(String email) {
        String normalizedEmail = email != null ? email.trim().toLowerCase() : "";
        PendingRegistration pending = pendingRegistrations.get(normalizedEmail);
        if (pending != null) {
            int codeInt = 1000 + RANDOM.nextInt(9000);
            String otpCode = String.valueOf(codeInt);
            pending.setOtpCode(otpCode);
            pending.setExpiresAt(LocalDateTime.now().plusMinutes(otpExpirationMinutes));
            pending.setAttempts(0);

            String magicLinkUrl = String.format("%s/verify-email?token=%s", frontendUrl, pending.getMagicToken());
            sendHtmlVerificationEmail(normalizedEmail, pending.getFullName(), otpCode, magicLinkUrl);
            log.info("Resent 4-digit OTP [{}] to: {}", otpCode, normalizedEmail);
            return;
        }

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new IllegalArgumentException("No pending registration found for email: " + email));
        createAndSendVerification(user, "REGISTRATION");
    }

    @Async
    public void sendHtmlVerificationEmail(String toEmail, String fullName, String otpCode, String magicLinkUrl) {
        try {
            if (mailSender == null) {
                log.info("[MOCK EMAIL] To: {} | OTP Code: {} | Link: {}", toEmail, otpCode, magicLinkUrl);
                return;
            }

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            String targetEmail = (toEmail != null) ? toEmail.trim().toLowerCase() : "";
            String fromAddress = (mailUsername != null && mailUsername.contains("@")) ? mailUsername.trim() : "kriteshjaiswal0007@gmail.com";
            
            helper.setFrom(fromAddress, "DocuMind AI");
            helper.setTo(targetEmail);
            helper.setSubject(String.format("%s is your DocuMind Verification Code", otpCode));

            String plainText = String.format("""
                Hello %s,

                Your DocuMind AI 4-digit verification code is: %s
                This code is valid for %d minutes.

                Verification link:
                %s

                If you did not request this verification, you can safely ignore this email.
                -- DocuMind AI Team
                """, fullName != null ? fullName : "User", otpCode, otpExpirationMinutes, magicLinkUrl);

            String htmlBody = String.format("""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #050816; color: #f8fafc; margin: 0; padding: 24px; }
                        .container { max-width: 520px; margin: 0 auto; background-color: #0b1120; border: 1px solid #1e293b; border-radius: 16px; padding: 32px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }
                        .logo { font-size: 20px; font-weight: 800; color: #38bdf8; text-align: center; margin-bottom: 24px; letter-spacing: -0.5px; }
                        .title { font-size: 22px; font-weight: 700; color: #ffffff; text-align: center; margin-bottom: 12px; }
                        .desc { font-size: 14px; color: #94a3b8; line-height: 1.6; text-align: center; margin-bottom: 28px; }
                        .otp-box { background: linear-gradient(135deg, rgba(56, 189, 248, 0.1), rgba(99, 102, 241, 0.15)); border: 2px dashed #6366f1; border-radius: 12px; padding: 18px; text-align: center; margin-bottom: 28px; }
                        .otp-code { font-size: 36px; font-weight: 800; letter-spacing: 12px; color: #38bdf8; font-family: monospace; }
                        .btn-container { text-align: center; margin-bottom: 24px; }
                        .btn { display: inline-block; background: linear-gradient(to right, #2563eb, #6366f1); color: #ffffff !important; text-decoration: none; font-weight: 700; font-size: 14px; padding: 14px 28px; border-radius: 10px; box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4); }
                        .footer { font-size: 12px; color: #64748b; text-align: center; margin-top: 32px; border-top: 1px solid #1e293b; padding-top: 18px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="logo">⚡ DocuMind AI</div>
                        <div class="title">Verify Your Email Address</div>
                        <div class="desc">Hello %s,<br>Please use the 4-digit verification code below to complete your DocuMind account verification. This code is valid for <strong>%d minutes</strong>.</div>
                        
                        <div class="otp-box">
                            <div class="otp-code">%s</div>
                        </div>

                        <div class="desc">Or click the button below to verify your account with one click:</div>
                        
                        <div class="btn-container">
                            <a href="%s" class="btn" target="_blank">Verify Email Instantly</a>
                        </div>

                        <div class="footer">
                            If you did not request this email, please safely ignore it.<br>
                            &copy; 2026 DocuMind AI Document Systems. All rights reserved.
                        </div>
                    </div>
                </body>
                </html>
            """, fullName != null ? fullName : "User", otpExpirationMinutes, otpCode, magicLinkUrl);

            helper.setText(plainText, htmlBody);
            mailSender.send(message);
            log.info("HTML verification email sent successfully to: {}", targetEmail);
            log.info("==========> [VERIFICATION OTP FOR {}]: {} <==========", targetEmail, otpCode);
        } catch (Exception e) {
            log.error("Could not deliver SMTP email to {}: {}. Fallback OTP code is: {}", toEmail, e.getMessage(), otpCode);
            log.info("==========> [VERIFICATION OTP FOR {}]: {} <==========", toEmail, otpCode);
        }
    }
}
