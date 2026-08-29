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
public class SessionResponseDto {

    private String sessionId;
    private String ipAddress;
    private String userAgent;
    private String deviceType;
    private LocalDateTime createdAt;
    private LocalDateTime lastActivityAt;
    private LocalDateTime expiresAt;
    private boolean active;
    private boolean current;
}
