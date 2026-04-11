package com.facebook.auth.controller;

import com.facebook.auth.model.dto.TwoFactorSetupResponse;
import com.facebook.auth.service.TwoFactorService;
import com.facebook.auth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/2fa")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Two-Factor Authentication", description = "TOTP-based 2FA management endpoints")
@SecurityRequirement(name = "bearerAuth")
public class TwoFactorController {

    private final TwoFactorService twoFactorService;
    private final UserService userService;

    @PostMapping("/setup")
    @Operation(summary = "Initialize TOTP 2FA setup and return secret and QR code URI")
    public ResponseEntity<TwoFactorSetupResponse> setup(@AuthenticationPrincipal UUID userId) {
        // Fetch email for QR code URI label
        String email = userService.getUserProfile(userId).email();
        TwoFactorSetupResponse response = twoFactorService.setupTwoFactor(userId, email);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify TOTP code and enable 2FA")
    public ResponseEntity<Map<String, String>> verify(
            @AuthenticationPrincipal UUID userId,
            @RequestBody Map<String, String> body) {

        String code = body.get("code");
        twoFactorService.enableTwoFactor(userId, code);
        return ResponseEntity.ok(Map.of("message", "Two-factor authentication enabled successfully"));
    }

    @PostMapping("/disable")
    @Operation(summary = "Disable 2FA (requires valid TOTP code)")
    public ResponseEntity<Map<String, String>> disable(
            @AuthenticationPrincipal UUID userId,
            @RequestBody Map<String, String> body) {

        String code = body.get("code");
        twoFactorService.disableTwoFactor(userId, code);
        return ResponseEntity.ok(Map.of("message", "Two-factor authentication disabled successfully"));
    }

    @GetMapping("/backup-codes")
    @Operation(summary = "Regenerate backup codes")
    public ResponseEntity<Map<String, List<String>>> regenerateBackupCodes(@AuthenticationPrincipal UUID userId) {
        List<String> codes = twoFactorService.regenerateBackupCodes(userId);
        return ResponseEntity.ok(Map.of("backupCodes", codes));
    }
}
