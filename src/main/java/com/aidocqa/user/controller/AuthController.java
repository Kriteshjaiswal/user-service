package com.aidocqa.user.controller;

import com.aidocqa.user.dto.*;
import com.aidocqa.user.security.UserPrincipal;
import com.aidocqa.user.service.AuthService;
import com.aidocqa.user.service.OAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication & Sessions", description = "Endpoints for registration, 4-digit OTP verification, OAuth, and session management")
public class AuthController {

    private final AuthService authService;
    private final OAuthService oauthService;

    @PostMapping("/register")
    @Operation(summary = "Register user", description = "Creates account and sends a 4-digit verification OTP and magic link to email")
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> register(
            @Valid @RequestBody RegisterRequestDto request,
            HttpServletRequest httpRequest) {

        String ip = extractClientIp(httpRequest);
        String ua = httpRequest.getHeader("User-Agent");
        AuthResponseDto response = authService.register(request, ip, ua);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponseDto.success(response.getMessage(), response));
    }

    @PostMapping("/login")
    @Operation(summary = "Login", description = "Authenticates user and creates a sliding 10-minute active session")
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> login(
            @Valid @RequestBody LoginRequestDto request,
            HttpServletRequest httpRequest) {

        String ip = extractClientIp(httpRequest);
        String ua = httpRequest.getHeader("User-Agent");
        AuthResponseDto response = authService.login(request, ip, ua);

        return ResponseEntity.ok(ApiResponseDto.success(response.getMessage(), response));
    }

    @PostMapping("/verify-otp")
    @Operation(summary = "Verify 4-digit OTP", description = "Validates the 4-digit email OTP and logs the user in")
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> verifyOtp(
            @Valid @RequestBody VerifyOtpRequestDto request,
            HttpServletRequest httpRequest) {

        String ip = extractClientIp(httpRequest);
        String ua = httpRequest.getHeader("User-Agent");
        AuthResponseDto response = authService.verifyOtpAndLogin(request, ip, ua);

        return ResponseEntity.ok(ApiResponseDto.success(response.getMessage(), response));
    }

    @PostMapping("/verify-link")
    @Operation(summary = "Verify Magic Link", description = "Validates the 1-click email magic link token and logs the user in")
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> verifyLink(
            @Valid @RequestBody VerifyLinkRequestDto request,
            HttpServletRequest httpRequest) {

        String ip = extractClientIp(httpRequest);
        String ua = httpRequest.getHeader("User-Agent");
        AuthResponseDto response = authService.verifyMagicLinkAndLogin(request.getToken(), ip, ua);

        return ResponseEntity.ok(ApiResponseDto.success(response.getMessage(), response));
    }

    @PostMapping("/resend-otp")
    @Operation(summary = "Resend 4-digit OTP", description = "Generates a fresh 4-digit OTP and dispatches verification email")
    public ResponseEntity<ApiResponseDto<Void>> resendOtp(@RequestParam String email) {
        authService.resendOtp(email);
        return ResponseEntity.ok(ApiResponseDto.success("A fresh 4-digit verification code has been sent to your email."));
    }

    @PostMapping("/oauth/{provider}")
    @Operation(summary = "OAuth Login", description = "Authenticates via Google or GitHub OAuth authorization code")
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> oauthLogin(
            @PathVariable String provider,
            @Valid @RequestBody OAuthLoginRequestDto request,
            HttpServletRequest httpRequest) {

        String ip = extractClientIp(httpRequest);
        String ua = httpRequest.getHeader("User-Agent");
        AuthResponseDto response = authService.oauthLogin(provider, request, ip, ua);

        return ResponseEntity.ok(ApiResponseDto.success(response.getMessage(), response));
    }

    @GetMapping("/oauth/config")
    @Operation(summary = "Get OAuth Status", description = "Returns Google and GitHub OAuth client configuration readiness")
    public ResponseEntity<ApiResponseDto<OAuthConfigDto>> getOAuthConfig() {
        return ResponseEntity.ok(ApiResponseDto.success("OAuth configuration retrieved", oauthService.getOAuthConfig()));
    }

    @PostMapping("/set-password")
    @Operation(summary = "Set Local Password", description = "Allows OAuth users or verified users to set a local password")
    public ResponseEntity<ApiResponseDto<UserResponseDto>> setPassword(
            @Valid @RequestBody SetPasswordRequestDto request,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        String ip = extractClientIp(httpRequest);
        UserResponseDto updated = authService.setPassword(principal.getUser().getId(), request, ip);
        return ResponseEntity.ok(ApiResponseDto.success("Password created successfully. You can now also log in using your email and password.", updated));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout", description = "Terminates current user session")
    public ResponseEntity<ApiResponseDto<Void>> logout(
            @AuthenticationPrincipal UserPrincipal principal) {

        if (principal != null) {
            authService.logout(principal.getCurrentSessionId(), principal.getUser().getId());
        }
        return ResponseEntity.ok(ApiResponseDto.success("Logged out successfully."));
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
