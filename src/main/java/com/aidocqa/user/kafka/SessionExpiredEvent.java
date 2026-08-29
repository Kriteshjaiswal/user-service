package com.aidocqa.user.kafka;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionExpiredEvent {
    private String sessionId;
    private Long userId;
    private String reason; // INACTIVITY_10_MIN, MANUAL_LOGOUT, REMOTE_REVOKE
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
}
