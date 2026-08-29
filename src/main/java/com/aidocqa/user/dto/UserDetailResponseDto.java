package com.aidocqa.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDetailResponseDto {

    private UserResponseDto user;
    private List<SessionResponseDto> activeSessions;
    private List<AuditLogResponseDto> recentAuditLogs;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuditLogResponseDto {
        private Long id;
        private String action;
        private String ipAddress;
        private String userAgent;
        private String details;
        private String timestamp;
    }
}
