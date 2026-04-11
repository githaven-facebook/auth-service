package com.facebook.auth.security;

import com.facebook.auth.config.JwtConfig;
import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtTokenProvider")
class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;
    private JwtConfig jwtConfig;

    private static final UUID USER_ID = UUID.randomUUID();
    private static final String EMAIL = "test@facebook.com";
    private static final Set<String> ROLES = Set.of("USER");
    private static final Set<String> PERMISSIONS = Set.of("api:read", "user:read:own");

    @BeforeEach
    void setUp() {
        jwtConfig = new JwtConfig();
        jwtConfig.setSecret("test-secret-key-for-unit-tests-must-be-at-least-256-bits-long-padding");
        jwtConfig.setAccessTokenExpirySeconds(900);
        jwtConfig.setRefreshTokenExpirySeconds(604800);
        jwtConfig.setIssuer("https://auth.facebook.com");

        jwtTokenProvider = new JwtTokenProvider(jwtConfig);
    }

    @Nested
    @DisplayName("generateAccessToken")
    class GenerateAccessTokenTests {

        @Test
        @DisplayName("generates valid access token with correct claims")
        void generateAccessToken_validInput_returnsToken() {
            String token = jwtTokenProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);

            assertThat(token).isNotBlank();
            assertThat(jwtTokenProvider.isAccessToken(token)).isTrue();
            assertThat(jwtTokenProvider.isRefreshToken(token)).isFalse();
        }

        @Test
        @DisplayName("extracts correct user ID from access token")
        void generateAccessToken_extractUserId_returnsCorrectId() {
            String token = jwtTokenProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);

            assertThat(jwtTokenProvider.extractUserId(token)).isEqualTo(USER_ID);
        }

        @Test
        @DisplayName("extracts correct roles from access token")
        void generateAccessToken_extractRoles_returnsCorrectRoles() {
            String token = jwtTokenProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);

            assertThat(jwtTokenProvider.extractRoles(token)).containsExactlyInAnyOrderElementsOf(ROLES);
        }

        @Test
        @DisplayName("extracts correct permissions from access token")
        void generateAccessToken_extractPermissions_returnsCorrectPermissions() {
            String token = jwtTokenProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);

            assertThat(jwtTokenProvider.extractPermissions(token)).containsExactlyInAnyOrderElementsOf(PERMISSIONS);
        }

        @Test
        @DisplayName("generates unique jti per token")
        void generateAccessToken_uniqueJti_eachToken() {
            String token1 = jwtTokenProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);
            String token2 = jwtTokenProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);

            assertThat(jwtTokenProvider.extractTokenId(token1))
                .isNotEqualTo(jwtTokenProvider.extractTokenId(token2));
        }
    }

    @Nested
    @DisplayName("generateRefreshToken")
    class GenerateRefreshTokenTests {

        @Test
        @DisplayName("generates valid refresh token")
        void generateRefreshToken_validInput_returnsToken() {
            String token = jwtTokenProvider.generateRefreshToken(USER_ID);

            assertThat(token).isNotBlank();
            assertThat(jwtTokenProvider.isRefreshToken(token)).isTrue();
            assertThat(jwtTokenProvider.isAccessToken(token)).isFalse();
        }

        @Test
        @DisplayName("extracts correct user ID from refresh token")
        void generateRefreshToken_extractUserId_correct() {
            String token = jwtTokenProvider.generateRefreshToken(USER_ID);

            assertThat(jwtTokenProvider.extractUserId(token)).isEqualTo(USER_ID);
        }
    }

    @Nested
    @DisplayName("validateAndExtractClaims")
    class ValidationTests {

        @Test
        @DisplayName("returns claims for valid token")
        void validate_validToken_returnsClaims() {
            String token = jwtTokenProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);

            Claims claims = jwtTokenProvider.validateAndExtractClaims(token);

            assertThat(claims.getSubject()).isEqualTo(USER_ID.toString());
            assertThat(claims.getIssuer()).isEqualTo("https://auth.facebook.com");
        }

        @Test
        @DisplayName("throws TOKEN_INVALID for malformed token")
        void validate_malformedToken_throwsTokenInvalid() {
            assertThatThrownBy(() -> jwtTokenProvider.validateAndExtractClaims("not.a.jwt"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.TOKEN_INVALID));
        }

        @Test
        @DisplayName("throws TOKEN_INVALID for token signed with different key")
        void validate_wrongSignature_throwsTokenInvalid() {
            JwtConfig otherConfig = new JwtConfig();
            otherConfig.setSecret("completely-different-secret-key-also-must-be-at-least-256-bits-for-test");
            otherConfig.setAccessTokenExpirySeconds(900);
            otherConfig.setRefreshTokenExpirySeconds(604800);
            otherConfig.setIssuer("https://auth.facebook.com");

            JwtTokenProvider otherProvider = new JwtTokenProvider(otherConfig);
            String tokenFromOther = otherProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);

            assertThatThrownBy(() -> jwtTokenProvider.validateAndExtractClaims(tokenFromOther))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.TOKEN_INVALID));
        }

        @Test
        @DisplayName("throws TOKEN_EXPIRED for expired token")
        void validate_expiredToken_throwsTokenExpired() {
            JwtConfig expiredConfig = new JwtConfig();
            expiredConfig.setSecret("test-secret-key-for-unit-tests-must-be-at-least-256-bits-long-padding");
            expiredConfig.setAccessTokenExpirySeconds(-1); // Already expired
            expiredConfig.setRefreshTokenExpirySeconds(604800);
            expiredConfig.setIssuer("https://auth.facebook.com");

            JwtTokenProvider expiredProvider = new JwtTokenProvider(expiredConfig);
            String expiredToken = expiredProvider.generateAccessToken(USER_ID, EMAIL, ROLES, PERMISSIONS);

            assertThatThrownBy(() -> jwtTokenProvider.validateAndExtractClaims(expiredToken))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.TOKEN_EXPIRED));
        }
    }
}
