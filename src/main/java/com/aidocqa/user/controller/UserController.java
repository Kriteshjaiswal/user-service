package com.aidocqa.user.controller;

import com.aidocqa.user.dto.ApiResponseDto;
import com.aidocqa.user.dto.UserDetailResponseDto;
import com.aidocqa.user.dto.UserResponseDto;
import com.aidocqa.user.security.UserPrincipal;
import com.aidocqa.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "User Directory & Management", description = "Endpoints for managing user profiles, directory search, and administrative controls")
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    @Operation(summary = "Get current user profile", description = "Retrieves profile and active sessions count of logged-in user")
    public ResponseEntity<ApiResponseDto<UserResponseDto>> getMe(
            @AuthenticationPrincipal UserPrincipal principal) {

        UserResponseDto profile = userService.getCurrentUserProfile(principal.getUser(), principal.getCurrentSessionId());
        return ResponseEntity.ok(ApiResponseDto.success("Profile retrieved", profile));
    }

    @PutMapping("/me")
    @Operation(summary = "Update profile", description = "Updates full name and avatar URL")
    public ResponseEntity<ApiResponseDto<UserResponseDto>> updateMe(
            @RequestBody Map<String, String> payload,
            @AuthenticationPrincipal UserPrincipal principal) {

        String fullName = payload.get("fullName");
        String avatarUrl = payload.get("avatarUrl");
        UserResponseDto updated = userService.updateProfile(principal.getUser().getId(), fullName, avatarUrl);
        return ResponseEntity.ok(ApiResponseDto.success("Profile updated successfully", updated));
    }

    @GetMapping("/all")
    @Operation(summary = "List all users", description = "Search and filter user directory by role, provider, and account status with pagination")
    public ResponseEntity<ApiResponseDto<Page<UserResponseDto>>> getAllUsers(
            @RequestParam(required = false) String query,
            @RequestParam(required = false) String role,
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String direction) {

        Sort sort = "desc".equalsIgnoreCase(direction) ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
        Page<UserResponseDto> users = userService.getAllUsers(query, role, provider, status, PageRequest.of(page, size, sort));
        return ResponseEntity.ok(ApiResponseDto.success("Users retrieved", users));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get user details", description = "Retrieves full user detail, active sessions list, and audit logs")
    public ResponseEntity<ApiResponseDto<UserDetailResponseDto>> getUserDetail(
            @PathVariable Long id,
            @AuthenticationPrincipal UserPrincipal principal) {

        UserDetailResponseDto detail = userService.getUserDetail(id, principal != null ? principal.getCurrentSessionId() : null);
        return ResponseEntity.ok(ApiResponseDto.success("User details retrieved", detail));
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Update user role/status (Admin)", description = "Updates role (ROLE_USER, ROLE_ADMIN) or status (ACTIVE, SUSPENDED)")
    public ResponseEntity<ApiResponseDto<UserResponseDto>> updateUserStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> payload) {

        String role = payload.get("role");
        String status = payload.get("status");
        UserResponseDto updated = userService.updateUserStatus(id, role, status);
        return ResponseEntity.ok(ApiResponseDto.success("User status updated", updated));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.user.id")
    @Operation(summary = "Delete user", description = "Deletes user account, invalidates sessions, and broadcasts Kafka deletion event")
    public ResponseEntity<ApiResponseDto<Void>> deleteUser(
            @PathVariable Long id) {

        userService.deleteUser(id);
        return ResponseEntity.ok(ApiResponseDto.success("User deleted successfully."));
    }
}
