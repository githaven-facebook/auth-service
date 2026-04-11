package com.facebook.auth.controller;

import com.facebook.auth.config.RateLimitConfig;
import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.dto.*;
import com.facebook.auth.service.AuthService;
import com.facebook.auth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication and token management endpoints")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final RateLimitConfig rateLimitConfig;

    @PostMapping("/login")
    @Operation(summary = "Authenticate user and issue tokens")
    public ResponseEntity<TokenResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String ipAddress = getClientIp(httpRequest);

        if (!rateLimitConfig.getLoginBucket(ipAddress).tryConsume(1)) {
            throw new AuthException(ErrorCode.RATE_LIMIT_EXCEEDED);
        }

        TokenResponse response = authService.login(
            request,
            ipAddress,
            httpRequest.getHeader("User-Agent")
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    @Operation(summary = "Register a new user account")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse response = userService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/logout")
    @Operation(summary = "Invalidate tokens and revoke session")
    public ResponseEntity<Void> logout(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest,
            @AuthenticationPrincipal UUID userId) {

        String accessToken = authHeader.substring("Bearer ".length());
        String refreshToken = refreshTokenRequest != null ? refreshTokenRequest.refreshToken() : null;

        authService.logout(accessToken, refreshToken, userId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token using refresh token")
    public ResponseEntity<TokenResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {

        TokenResponse response = authService.refreshToken(
            request.refreshToken(),
            getClientIp(httpRequest),
            httpRequest.getHeader("User-Agent")
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
    @Operation(summary = "Verify email address with token")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam String token) {
        userService.verifyEmail(token);
        return ResponseEntity.ok(Map.of("message", "Email verified successfully"));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Initiate password reset flow")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest httpRequest) {

        String ipAddress = getClientIp(httpRequest);
        if (!rateLimitConfig.getLoginBucket(ipAddress).tryConsume(1)) {
            throw new AuthException(ErrorCode.RATE_LIMIT_EXCEEDED);
        }

        userService.initiatePasswordReset(request.email());
        return ResponseEntity.ok(Map.of("message", "If that email address is registered, a password reset link has been sent"));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Complete password reset with token")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        userService.resetPassword(request.token(), request.newPassword());
        return ResponseEntity.ok(Map.of("message", "Password reset successfully"));
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}
