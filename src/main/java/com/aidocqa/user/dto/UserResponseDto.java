package com.aidocqa.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponseDto {

    private Long id;
    private String fullName;
    private String email;
    private String role;
    private String provider; // LOCAL, GOOGLE, GITHUB
    private String avatarUrl;
    private boolean emailVerified;
    private boolean hasPassword;
    private String accountStatus; // ACTIVE, PENDING_VERIFICATION, SUSPENDED
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private int activeSessionsCount;
    private LocalDateTime lastActiveAt;
}
