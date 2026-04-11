package com.facebook.auth.service;

import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.dto.RegisterRequest;
import com.facebook.auth.model.dto.UserResponse;
import com.facebook.auth.model.entity.Role;
import com.facebook.auth.model.entity.User;
import com.facebook.auth.repository.RoleRepository;
import com.facebook.auth.repository.TwoFactorSecretRepository;
import com.facebook.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserService")
class UserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private TwoFactorSecretRepository twoFactorSecretRepository;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    private static final UUID USER_ID = UUID.randomUUID();
    private static final String EMAIL = "user@facebook.com";
    private static final String USERNAME = "fbuser";
    private static final String PASSWORD = "Password@123";

    private Role defaultRole;
    private User savedUser;

    @BeforeEach
    void setUp() {
        defaultRole = Role.builder().id(1L).name("USER").description("Default user role").build();
        savedUser = User.builder()
            .id(USER_ID)
            .email(EMAIL)
            .username(USERNAME)
            .passwordHash("hashed")
            .displayName("FB User")
            .emailVerified(false)
            .accountLocked(false)
            .roles(Set.of(defaultRole))
            .build();
    }

    @Nested
    @DisplayName("register")
    class RegisterTests {

        @Test
        @DisplayName("successfully registers a new user")
        void register_newUser_returnsUserResponse() {
            RegisterRequest request = new RegisterRequest(EMAIL, USERNAME, PASSWORD, "FB User");
            when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
            when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
            when(roleRepository.findByName("USER")).thenReturn(Optional.of(defaultRole));
            when(passwordEncoder.encode(PASSWORD)).thenReturn("hashed");
            when(userRepository.save(any(User.class))).thenReturn(savedUser);

            UserResponse response = userService.register(request);

            assertThat(response.email()).isEqualTo(EMAIL);
            assertThat(response.username()).isEqualTo(USERNAME);
            assertThat(response.emailVerified()).isFalse();

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getPasswordHash()).isEqualTo("hashed");
            assertThat(userCaptor.getValue().getEmailVerificationToken()).isNotNull();
        }

        @Test
        @DisplayName("throws EMAIL_ALREADY_EXISTS for duplicate email")
        void register_duplicateEmail_throwsConflict() {
            when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

            assertThatThrownBy(() -> userService.register(new RegisterRequest(EMAIL, USERNAME, PASSWORD, null)))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode()).isEqualTo(ErrorCode.EMAIL_ALREADY_EXISTS));
        }

        @Test
        @DisplayName("throws USERNAME_ALREADY_EXISTS for duplicate username")
        void register_duplicateUsername_throwsConflict() {
            when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
            when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

            assertThatThrownBy(() -> userService.register(new RegisterRequest(EMAIL, USERNAME, PASSWORD, null)))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode()).isEqualTo(ErrorCode.USERNAME_ALREADY_EXISTS));
        }
    }

    @Nested
    @DisplayName("verifyEmail")
    class VerifyEmailTests {

        @Test
        @DisplayName("marks email as verified on valid token")
        void verifyEmail_validToken_setsEmailVerified() {
            String token = UUID.randomUUID().toString();
            savedUser.setEmailVerificationToken(token);
            when(userRepository.findByEmailVerificationToken(token)).thenReturn(Optional.of(savedUser));
            when(userRepository.save(any(User.class))).thenReturn(savedUser);

            userService.verifyEmail(token);

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            assertThat(captor.getValue().isEmailVerified()).isTrue();
            assertThat(captor.getValue().getEmailVerificationToken()).isNull();
        }

        @Test
        @DisplayName("throws INVALID_EMAIL_VERIFICATION_TOKEN on unknown token")
        void verifyEmail_invalidToken_throws() {
            when(userRepository.findByEmailVerificationToken("bad-token")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.verifyEmail("bad-token"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.INVALID_EMAIL_VERIFICATION_TOKEN));
        }
    }

    @Nested
    @DisplayName("resetPassword")
    class ResetPasswordTests {

        @Test
        @DisplayName("resets password on valid non-expired token")
        void resetPassword_validToken_updatesPassword() {
            String token = UUID.randomUUID().toString();
            savedUser.setPasswordResetToken(token);
            savedUser.setPasswordResetExpiresAt(Instant.now().plusSeconds(3600));
            when(userRepository.findByPasswordResetToken(token)).thenReturn(Optional.of(savedUser));
            when(passwordEncoder.encode("NewPass@123")).thenReturn("new-hashed");
            when(userRepository.save(any(User.class))).thenReturn(savedUser);

            userService.resetPassword(token, "NewPass@123");

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            assertThat(captor.getValue().getPasswordHash()).isEqualTo("new-hashed");
            assertThat(captor.getValue().getPasswordResetToken()).isNull();
            assertThat(captor.getValue().isAccountLocked()).isFalse();
        }

        @Test
        @DisplayName("throws INVALID_PASSWORD_RESET_TOKEN on expired token")
        void resetPassword_expiredToken_throws() {
            String token = UUID.randomUUID().toString();
            savedUser.setPasswordResetToken(token);
            savedUser.setPasswordResetExpiresAt(Instant.now().minusSeconds(3600));
            when(userRepository.findByPasswordResetToken(token)).thenReturn(Optional.of(savedUser));

            assertThatThrownBy(() -> userService.resetPassword(token, "NewPass@123"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.INVALID_PASSWORD_RESET_TOKEN));
        }
    }
}
