package com.aidocqa.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyOtpRequestDto {

    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "OTP code is required")
    @Pattern(regexp = "^[0-9]{4}$", message = "OTP must be exactly 4 digits")
    private String otpCode;
}
