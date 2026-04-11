package com.facebook.auth.service;

import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.dto.RegisterRequest;
import com.facebook.auth.model.dto.UserResponse;
import com.facebook.auth.model.entity.Role;
import com.facebook.auth.model.entity.TwoFactorSecret;
import com.facebook.auth.model.entity.User;
import com.facebook.auth.repository.RoleRepository;
import com.facebook.auth.repository.TwoFactorSecretRepository;
import com.facebook.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private static final String DEFAULT_ROLE = "USER";
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long PASSWORD_RESET_TOKEN_TTL_HOURS = 2;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TwoFactorSecretRepository twoFactorSecretRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new AuthException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }
        if (userRepository.existsByUsername(request.username())) {
            throw new AuthException(ErrorCode.USERNAME_ALREADY_EXISTS);
        }

        Role defaultRole = roleRepository.findByName(DEFAULT_ROLE)
            .orElseGet(() -> {
                Role role = Role.builder().name(DEFAULT_ROLE).description("Default user role").build();
                return roleRepository.save(role);
            });

        String verificationToken = UUID.randomUUID().toString();

        User user = User.builder()
            .email(request.email())
            .username(request.username())
            .passwordHash(passwordEncoder.encode(request.password()))
            .displayName(request.displayName())
            .emailVerified(false)
            .accountLocked(false)
            .failedLoginAttempts(0)
            .emailVerificationToken(verificationToken)
            .roles(Set.of(defaultRole))
            .build();

        user = userRepository.save(user);
        log.info("Registered new user: {}", user.getEmail());

        // TODO: Send verification email via email service
        log.debug("Email verification token for {}: {}", user.getEmail(), verificationToken);

        return toUserResponse(user, false);
    }

    @Transactional
    public void verifyEmail(String token) {
        User user = userRepository.findByEmailVerificationToken(token)
            .orElseThrow(() -> new AuthException(ErrorCode.INVALID_EMAIL_VERIFICATION_TOKEN));

        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        userRepository.save(user);
        log.info("Email verified for user: {}", user.getEmail());
    }

    @Transactional
    public void initiatePasswordReset(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            String resetToken = UUID.randomUUID().toString();
            user.setPasswordResetToken(resetToken);
            user.setPasswordResetExpiresAt(Instant.now().plus(PASSWORD_RESET_TOKEN_TTL_HOURS, ChronoUnit.HOURS));
            userRepository.save(user);
            // TODO: Send password reset email
            log.debug("Password reset token for {}: {}", email, resetToken);
        });
        // Always succeed to prevent email enumeration
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        User user = userRepository.findByPasswordResetToken(token)
            .orElseThrow(() -> new AuthException(ErrorCode.INVALID_PASSWORD_RESET_TOKEN));

        if (user.getPasswordResetExpiresAt() == null || user.getPasswordResetExpiresAt().isBefore(Instant.now())) {
            throw new AuthException(ErrorCode.INVALID_PASSWORD_RESET_TOKEN);
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetExpiresAt(null);
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        userRepository.save(user);
        log.info("Password reset for user: {}", user.getEmail());
    }

    @Transactional
    public void changePassword(UUID userId, String currentPassword, String newPassword) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        log.info("Password changed for user: {}", user.getEmail());
    }

    @Transactional
    public void lockAccount(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
        user.setAccountLocked(true);
        userRepository.save(user);
        log.warn("Account locked for user: {}", user.getEmail());
    }

    @Transactional
    public void recordFailedLogin(UUID userId) {
        userRepository.incrementFailedLoginAttempts(userId);
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setAccountLocked(true);
            userRepository.save(user);
            log.warn("Account locked due to {} failed login attempts: {}", MAX_FAILED_ATTEMPTS, user.getEmail());
        }
    }

    @Transactional(readOnly = true)
    public UserResponse getUserProfile(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        boolean twoFactorEnabled = twoFactorSecretRepository.existsByUserIdAndEnabledTrue(userId);
        return toUserResponse(user, twoFactorEnabled);
    }

    @Transactional
    public UserResponse updateProfile(UUID userId, String displayName) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        if (displayName != null && !displayName.isBlank()) {
            user.setDisplayName(displayName);
        }

        user = userRepository.save(user);
        boolean twoFactorEnabled = twoFactorSecretRepository.existsByUserIdAndEnabledTrue(userId);
        return toUserResponse(user, twoFactorEnabled);
    }

    private UserResponse toUserResponse(User user, boolean twoFactorEnabled) {
        Set<String> roles = user.getRoles().stream()
            .map(Role::getName)
            .collect(Collectors.toSet());

        return new UserResponse(
            user.getId(),
            user.getEmail(),
            user.getUsername(),
            user.getDisplayName(),
            user.isEmailVerified(),
            user.isAccountLocked(),
            twoFactorEnabled,
            roles,
            user.getLastLoginAt(),
            user.getCreatedAt()
        );
    }
}
