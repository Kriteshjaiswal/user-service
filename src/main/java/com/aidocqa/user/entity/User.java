package com.aidocqa.user.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_user_email", columnList = "email"),
    @Index(name = "idx_user_provider", columnList = "provider, providerId")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String fullName;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = true)
    private String passwordHash;

    @Column(nullable = false)
    @Builder.Default
    private String role = "ROLE_USER";

    @Column(nullable = false)
    @Builder.Default
    private String provider = "LOCAL"; // LOCAL, GOOGLE, GITHUB

    private String providerId;

    private String avatarUrl;

    @Column(nullable = false)
    @Builder.Default
    private boolean isEmailVerified = false;

    @Column(nullable = false)
    @Builder.Default
    private String accountStatus = "ACTIVE"; // ACTIVE, PENDING_VERIFICATION, SUSPENDED

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    public boolean hasPassword() {
        return passwordHash != null && !passwordHash.isBlank();
    }
}
