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

    /**
     * Generates a 4-digit numeric OTP and a unique magic verification token,
     * stores it in the database with 10-minute validity, and sends the verification email.
     */
    @Transactional
    public UserVerification createAndSendVerification(User user, String type) {
        // Generate secure 4-digit numeric OTP (e.g. 1000 - 9999)
        int codeInt = 1000 + RANDOM.nextInt(9000);
        String otpCode = String.valueOf(codeInt);

        // Generate magic link token UUID
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

        // Construct magic link URL
        String magicLinkUrl = String.format("%s/verify-email?token=%s", frontendUrl, magicToken);

        // Publish to Kafka for asynchronous notification worker
        eventProducer.publishEmailOtp(EmailOtpEvent.builder()
                .recipientEmail(user.getEmail())
                .recipientName(user.getFullName())
                .otpCode(otpCode)
                .magicLinkUrl(magicLinkUrl)
                .expirationMinutes(otpExpirationMinutes)
                .build());

        // Send direct HTML email as well
        sendHtmlVerificationEmail(user.getEmail(), user.getFullName(), otpCode, magicLinkUrl);

        log.info("Generated 4-digit OTP [{}] for user: {} (Expires in {} mins)", otpCode, user.getEmail(), otpExpirationMinutes);
        return saved;
    }

    /**
     * Validates 4-digit OTP submitted by the user.
     */
    @Transactional
    public User verifyOtp(String email, String otpCode) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));

        UserVerification verification = verificationRepository
                .findTopByUserIdAndTypeAndIsUsedFalseOrderByCreatedAtDesc(user.getId(), "REGISTRATION")
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

        if (!verification.getOtpCode().equals(otpCode.trim())) {
            verificationRepository.save(verification);
            throw new IllegalArgumentException("Invalid 4-digit OTP. Please check your email and try again.");
        }

        // Mark verification used & activate user
        verification.setUsed(true);
        verificationRepository.save(verification);

        user.setEmailVerified(true);
        user.setAccountStatus("ACTIVE");
        User updatedUser = userRepository.save(user);

        // Publish Kafka UserVerifiedEvent
        eventProducer.publishUserVerified(UserVerifiedEvent.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .verifiedAt(LocalDateTime.now())
                .build());

        auditLogRepository.save(UserAuditLog.builder()
                .userId(user.getId())
                .action("OTP_VERIFIED")
                .details("4-digit OTP verified successfully via email code")
                .build());

        log.info("User {} successfully verified with OTP code.", user.getEmail());
        return updatedUser;
    }

    /**
     * Validates Magic Verification Link Token.
     */
    @Transactional
    public User verifyMagicLink(String token) {
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
        User updatedUser = userRepository.save(user);

        eventProducer.publishUserVerified(UserVerifiedEvent.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .verifiedAt(LocalDateTime.now())
                .build());

        auditLogRepository.save(UserAuditLog.builder()
                .userId(user.getId())
                .action("MAGIC_LINK_VERIFIED")
                .details("Email verified via 1-click magic link token")
                .build());

        log.info("User {} successfully verified via magic link.", user.getEmail());
        return updatedUser;
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

            helper.setTo(toEmail);
            helper.setSubject(String.format("%s is your DocuMind Verification Code", otpCode));

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

            helper.setText(htmlBody, true);
            mailSender.send(message);
            log.info("HTML verification email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.warn("Could not deliver SMTP email to {}: {}. (Falling back to console OTP: {})", toEmail, e.getMessage(), otpCode);
        }
    }
}
