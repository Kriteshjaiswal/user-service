package com.aidocqa.user.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_sessions", indexes = {
    @Index(name = "idx_session_user", columnList = "userId"),
    @Index(name = "idx_session_active", columnList = "isActive, expiresAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSession {

    @Id
    @Column(length = 100)
    private String id; // sess_... UUID or crypto random token

    @Column(nullable = false)
    private Long userId;

    private String ipAddress;

    @Column(length = 1000)
    private String userAgent;

    private String deviceType; // Desktop, Mobile, Tablet, Browser details

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime lastActivityAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    @Builder.Default
    private boolean isActive = true;
}
