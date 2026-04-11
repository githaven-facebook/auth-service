package com.facebook.auth.service;

import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.dto.LoginRequest;
import com.facebook.auth.model.dto.TokenResponse;
import com.facebook.auth.model.entity.Role;
import com.facebook.auth.model.entity.User;
import com.facebook.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService")
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private TokenService tokenService;
    @Mock private SessionService sessionService;
    @Mock private TwoFactorService twoFactorService;
    @Mock private UserService userService;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private static final UUID USER_ID = UUID.randomUUID();
    private static final String EMAIL = "test@facebook.com";
    private static final String PASSWORD = "Password@123";
    private static final String HASHED_PASSWORD = "$2a$12$hashedpassword";

    @BeforeEach
    void setUp() {
        Role userRole = Role.builder().id(1L).name("USER").build();
        testUser = User.builder()
            .id(USER_ID)
            .email(EMAIL)
            .username("testuser")
            .passwordHash(HASHED_PASSWORD)
            .emailVerified(true)
            .accountLocked(false)
            .failedLoginAttempts(0)
            .roles(Set.of(userRole))
            .build();
    }

    @Nested
    @DisplayName("login")
    class LoginTests {

        @Test
        @DisplayName("returns token pair on valid credentials")
        void login_validCredentials_returnsTokens() {
            LoginRequest request = new LoginRequest(EMAIL, PASSWORD, null);
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches(PASSWORD, HASHED_PASSWORD)).thenReturn(true);
            when(twoFactorService.isTwoFactorEnabled(USER_ID)).thenReturn(false);
            when(tokenService.generateAccessToken(any(), any(), any(), any())).thenReturn("access-token");
            when(tokenService.generateRefreshToken(USER_ID)).thenReturn("refresh-token");
            when(tokenService.getAccessTokenExpirySeconds()).thenReturn(900L);
            when(userRepository.save(any())).thenReturn(testUser);

            TokenResponse response = authService.login(request, "127.0.0.1", "TestAgent/1.0");

            assertThat(response.accessToken()).isEqualTo("access-token");
            assertThat(response.refreshToken()).isEqualTo("refresh-token");
            assertThat(response.tokenType()).isEqualTo("Bearer");
            verify(userRepository).resetFailedLoginAttempts(USER_ID);
            verify(sessionService).createSession(eq(USER_ID), eq("refresh-token"), eq("127.0.0.1"), eq("TestAgent/1.0"));
        }

        @Test
        @DisplayName("throws INVALID_CREDENTIALS when user not found")
        void login_userNotFound_throwsInvalidCredentials() {
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.login(new LoginRequest(EMAIL, PASSWORD, null), "127.0.0.1", "UA"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));
        }

        @Test
        @DisplayName("throws ACCOUNT_LOCKED when account is locked")
        void login_accountLocked_throwsAccountLocked() {
            testUser.setAccountLocked(true);
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> authService.login(new LoginRequest(EMAIL, PASSWORD, null), "127.0.0.1", "UA"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_LOCKED));
        }

        @Test
        @DisplayName("throws EMAIL_NOT_VERIFIED when email unverified")
        void login_emailNotVerified_throwsEmailNotVerified() {
            testUser.setEmailVerified(false);
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> authService.login(new LoginRequest(EMAIL, PASSWORD, null), "127.0.0.1", "UA"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode()).isEqualTo(ErrorCode.EMAIL_NOT_VERIFIED));
        }

        @Test
        @DisplayName("throws INVALID_CREDENTIALS on wrong password and increments counter")
        void login_wrongPassword_incrementsFailedAttempts() {
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches(PASSWORD, HASHED_PASSWORD)).thenReturn(false);

            assertThatThrownBy(() -> authService.login(new LoginRequest(EMAIL, PASSWORD, null), "127.0.0.1", "UA"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));

            verify(userService).recordFailedLogin(USER_ID);
        }

        @Test
        @DisplayName("throws TWO_FACTOR_REQUIRED when 2FA enabled but no code provided")
        void login_twoFactorRequired_noCode_throwsTwoFactorRequired() {
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches(PASSWORD, HASHED_PASSWORD)).thenReturn(true);
            when(twoFactorService.isTwoFactorEnabled(USER_ID)).thenReturn(true);

            assertThatThrownBy(() -> authService.login(new LoginRequest(EMAIL, PASSWORD, null), "127.0.0.1", "UA"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode()).isEqualTo(ErrorCode.TWO_FACTOR_REQUIRED));
        }

        @Test
        @DisplayName("succeeds when 2FA enabled and valid code provided")
        void login_twoFactorEnabled_validCode_succeeds() {
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches(PASSWORD, HASHED_PASSWORD)).thenReturn(true);
            when(twoFactorService.isTwoFactorEnabled(USER_ID)).thenReturn(true);
            doNothing().when(twoFactorService).verifyCode(USER_ID, "123456");
            when(tokenService.generateAccessToken(any(), any(), any(), any())).thenReturn("access-token");
            when(tokenService.generateRefreshToken(USER_ID)).thenReturn("refresh-token");
            when(tokenService.getAccessTokenExpirySeconds()).thenReturn(900L);
            when(userRepository.save(any())).thenReturn(testUser);

            TokenResponse response = authService.login(new LoginRequest(EMAIL, PASSWORD, "123456"), "127.0.0.1", "UA");

            assertThat(response.accessToken()).isEqualTo("access-token");
            verify(twoFactorService).verifyCode(USER_ID, "123456");
        }
    }

    @Nested
    @DisplayName("refreshToken")
    class RefreshTokenTests {

        @Test
        @DisplayName("rotates tokens on valid refresh token")
        void refreshToken_valid_returnsNewTokens() {
            when(tokenService.validateRefreshToken("old-refresh")).thenReturn(USER_ID);
            when(userRepository.findById(USER_ID)).thenReturn(Optional.of(testUser));
            when(tokenService.generateAccessToken(any(), any(), any(), any())).thenReturn("new-access");
            when(tokenService.generateRefreshToken(USER_ID)).thenReturn("new-refresh");
            when(tokenService.getAccessTokenExpirySeconds()).thenReturn(900L);

            TokenResponse response = authService.refreshToken("old-refresh", "127.0.0.1", "UA");

            assertThat(response.accessToken()).isEqualTo("new-access");
            assertThat(response.refreshToken()).isEqualTo("new-refresh");
            verify(tokenService).revokeToken("old-refresh");
        }

        @Test
        @DisplayName("throws ACCOUNT_LOCKED when account locked during refresh")
        void refreshToken_accountLocked_throws() {
            testUser.setAccountLocked(true);
            when(tokenService.validateRefreshToken("refresh-token")).thenReturn(USER_ID);
            when(userRepository.findById(USER_ID)).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> authService.refreshToken("refresh-token", "127.0.0.1", "UA"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_LOCKED));
        }
    }
}
