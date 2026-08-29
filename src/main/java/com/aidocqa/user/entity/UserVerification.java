package com.aidocqa.user.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_verifications", indexes = {
    @Index(name = "idx_verification_user", columnList = "userId, type"),
    @Index(name = "idx_verification_token", columnList = "token"),
    @Index(name = "idx_verification_otp", columnList = "userId, otpCode")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserVerification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false, length = 10)
    private String otpCode; // 4-digit code e.g. "8492"

    @Column(nullable = false, unique = true, length = 100)
    private String token; // Magic verification link UUID token

    @Column(nullable = false)
    @Builder.Default
    private String type = "REGISTRATION"; // REGISTRATION, PASSWORD_RESET, EMAIL_VERIFICATION

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    @Builder.Default
    private boolean isUsed = false;

    @Column(nullable = false)
    @Builder.Default
    private int attempts = 0;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}
