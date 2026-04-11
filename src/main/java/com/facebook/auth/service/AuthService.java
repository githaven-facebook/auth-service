package com.facebook.auth.service;

import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.dto.LoginRequest;
import com.facebook.auth.model.dto.TokenResponse;
import com.facebook.auth.model.entity.Permission;
import com.facebook.auth.model.entity.Role;
import com.facebook.auth.model.entity.User;
import com.facebook.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final TwoFactorService twoFactorService;
    private final UserService userService;

    @Transactional
    public TokenResponse login(LoginRequest request, String ipAddress, String userAgent) {
        User user = userRepository.findByEmail(request.email())
            .orElseThrow(() -> new AuthException(ErrorCode.INVALID_CREDENTIALS));

        if (user.isAccountLocked()) {
            throw new AuthException(ErrorCode.ACCOUNT_LOCKED);
        }

        if (!user.isEmailVerified()) {
            throw new AuthException(ErrorCode.EMAIL_NOT_VERIFIED);
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            userService.recordFailedLogin(user.getId());
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }

        // Check if 2FA is enabled
        boolean twoFactorEnabled = twoFactorService.isTwoFactorEnabled(user.getId());
        if (twoFactorEnabled) {
            if (!StringUtils.hasText(request.twoFactorCode())) {
                throw new AuthException(ErrorCode.TWO_FACTOR_REQUIRED);
            }
            twoFactorService.verifyCode(user.getId(), request.twoFactorCode());
        }

        // Successful login
        userRepository.resetFailedLoginAttempts(user.getId());
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        Set<String> roles = user.getRoles().stream()
            .map(Role::getName)
            .collect(Collectors.toSet());

        Set<String> permissions = user.getRoles().stream()
            .flatMap(role -> role.getPermissions().stream())
            .map(Permission::getName)
            .collect(Collectors.toSet());

        String accessToken = tokenService.generateAccessToken(user.getId(), user.getEmail(), roles, permissions);
        String refreshToken = tokenService.generateRefreshToken(user.getId());

        sessionService.createSession(user.getId(), refreshToken, ipAddress, userAgent);

        log.info("User logged in: {}", user.getEmail());
        return TokenResponse.of(accessToken, refreshToken, tokenService.getAccessTokenExpirySeconds());
    }

    @Transactional
    public void logout(String accessToken, String refreshToken, UUID userId) {
        tokenService.revokeToken(accessToken);
        if (StringUtils.hasText(refreshToken)) {
            tokenService.revokeToken(refreshToken);
            try {
                sessionService.revokeAllSessions(userId);
            } catch (Exception e) {
                log.warn("Could not revoke sessions for user {}: {}", userId, e.getMessage());
            }
        }
        log.info("User logged out: {}", userId);
    }

    @Transactional
    public TokenResponse refreshToken(String refreshToken, String ipAddress, String userAgent) {
        UUID userId = tokenService.validateRefreshToken(refreshToken);

        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        if (user.isAccountLocked()) {
            throw new AuthException(ErrorCode.ACCOUNT_LOCKED);
        }

        // Rotate refresh token
        tokenService.revokeToken(refreshToken);

        Set<String> roles = user.getRoles().stream()
            .map(Role::getName)
            .collect(Collectors.toSet());

        Set<String> permissions = user.getRoles().stream()
            .flatMap(role -> role.getPermissions().stream())
            .map(Permission::getName)
            .collect(Collectors.toSet());

        String newAccessToken = tokenService.generateAccessToken(user.getId(), user.getEmail(), roles, permissions);
        String newRefreshToken = tokenService.generateRefreshToken(user.getId());

        sessionService.createSession(user.getId(), newRefreshToken, ipAddress, userAgent);

        log.debug("Tokens refreshed for user: {}", userId);
        return TokenResponse.of(newAccessToken, newRefreshToken, tokenService.getAccessTokenExpirySeconds());
    }

    public long getAccessTokenExpirySeconds() {
        return tokenService.getAccessTokenExpirySeconds();
    }
}
