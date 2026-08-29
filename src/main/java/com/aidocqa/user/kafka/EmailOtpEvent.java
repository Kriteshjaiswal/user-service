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
public class EmailOtpEvent {
    private String recipientEmail;
    private String recipientName;
    private String otpCode;
    private String magicLinkUrl;
    private int expirationMinutes;
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
}
