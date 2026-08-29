package com.aidocqa.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDto {

    private String sessionId;
    private String token; // Optional JWT token for Authorization: Bearer header interoperability
    private UserResponseDto user;
    private boolean requiresOtpVerification;
    private String message;
}
