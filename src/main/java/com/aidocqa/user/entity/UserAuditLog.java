package com.aidocqa.user.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_audit_logs", indexes = {
    @Index(name = "idx_audit_user", columnList = "userId, timestamp")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;

    @Column(nullable = false)
    private String action; // LOGIN_SUCCESS, LOGIN_FAILED, OTP_SENT, OTP_VERIFIED, SESSION_EXPIRED, PASSWORD_SET, OAUTH_LOGIN

    private String ipAddress;

    private String userAgent;

    @Column(length = 1000)
    private String details;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime timestamp;
}
