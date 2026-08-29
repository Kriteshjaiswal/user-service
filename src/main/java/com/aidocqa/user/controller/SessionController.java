package com.aidocqa.user.controller;

import com.aidocqa.user.dto.ApiResponseDto;
import com.aidocqa.user.dto.SessionResponseDto;
import com.aidocqa.user.security.UserPrincipal;
import com.aidocqa.user.service.SessionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/sessions")
@RequiredArgsConstructor
@Tag(name = "Session Management", description = "Endpoints for viewing active devices/sessions and terminating remote sessions")
public class SessionController {

    private final SessionService sessionService;

    @GetMapping("/active")
    @Operation(summary = "List Active Sessions", description = "Lists all active device sessions for the authenticated user")
    public ResponseEntity<ApiResponseDto<List<SessionResponseDto>>> getActiveSessions(
            @AuthenticationPrincipal UserPrincipal principal) {

        List<SessionResponseDto> sessions = sessionService.getActiveSessions(
                principal.getUser().getId(),
                principal.getCurrentSessionId()
        );
        return ResponseEntity.ok(ApiResponseDto.success("Active sessions retrieved", sessions));
    }

    @DeleteMapping("/revoke/{sessionId}")
    @Operation(summary = "Revoke Specific Session", description = "Terminates a specific device session")
    public ResponseEntity<ApiResponseDto<Void>> revokeSession(
            @PathVariable String sessionId,
            @AuthenticationPrincipal UserPrincipal principal) {

        sessionService.revokeSession(sessionId, principal.getUser().getId());
        return ResponseEntity.ok(ApiResponseDto.success("Session revoked successfully."));
    }

    @DeleteMapping("/revoke-others")
    @Operation(summary = "Revoke Other Sessions", description = "Terminates all sessions across other devices except current one")
    public ResponseEntity<ApiResponseDto<Void>> revokeOtherSessions(
            @AuthenticationPrincipal UserPrincipal principal) {

        sessionService.revokeOtherSessions(principal.getUser().getId(), principal.getCurrentSessionId());
        return ResponseEntity.ok(ApiResponseDto.success("All other active device sessions have been terminated."));
    }
}
