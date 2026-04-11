package com.facebook.auth.service;

import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.dto.TwoFactorSetupResponse;
import com.facebook.auth.model.entity.TwoFactorSecret;
import com.facebook.auth.repository.TwoFactorSecretRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("TwoFactorService")
class TwoFactorServiceTest {

    @Mock private TwoFactorSecretRepository twoFactorSecretRepository;

    // Use real BCrypt for backup code verification tests
    private final PasswordEncoder realPasswordEncoder = new BCryptPasswordEncoder(4);

    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks
    private TwoFactorService twoFactorService;

    private static final UUID USER_ID = UUID.randomUUID();
    private static final String EMAIL = "user@facebook.com";

    @Nested
    @DisplayName("setupTwoFactor")
    class SetupTests {

        @Test
        @DisplayName("returns setup response with secret, QR URI, and backup codes")
        void setup_newUser_returnsSetupResponse() {
            when(twoFactorSecretRepository.existsByUserIdAndEnabledTrue(USER_ID)).thenReturn(false);
            when(twoFactorSecretRepository.findByUserId(USER_ID)).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("hashed-code");
            when(twoFactorSecretRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            TwoFactorSetupResponse response = twoFactorService.setupTwoFactor(USER_ID, EMAIL);

            assertThat(response.secret()).isNotBlank();
            assertThat(response.qrCodeUri()).contains("otpauth://totp/");
            assertThat(response.qrCodeUri()).contains(EMAIL);
            assertThat(response.backupCodes()).hasSize(8);
            assertThat(response.backupCodes()).allMatch(code -> code.length() == 10);
        }

        @Test
        @DisplayName("throws TWO_FACTOR_ALREADY_ENABLED when already active")
        void setup_alreadyEnabled_throws() {
            when(twoFactorSecretRepository.existsByUserIdAndEnabledTrue(USER_ID)).thenReturn(true);

            assertThatThrownBy(() -> twoFactorService.setupTwoFactor(USER_ID, EMAIL))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.TWO_FACTOR_ALREADY_ENABLED));
        }
    }

    @Nested
    @DisplayName("verifyCode")
    class VerifyCodeTests {

        @Test
        @DisplayName("throws TWO_FACTOR_NOT_ENABLED when no secret exists")
        void verifyCode_noSecret_throws() {
            when(twoFactorSecretRepository.findByUserId(USER_ID)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> twoFactorService.verifyCode(USER_ID, "123456"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.TWO_FACTOR_NOT_ENABLED));
        }

        @Test
        @DisplayName("throws TWO_FACTOR_INVALID on wrong TOTP code and no matching backup code")
        void verifyCode_invalidCode_throws() {
            TwoFactorSecret secret = TwoFactorSecret.builder()
                .id(UUID.randomUUID())
                .userId(USER_ID)
                .secret("JBSWY3DPEHPK3PXP")
                .enabled(true)
                .backupCodes(List.of())
                .build();
            when(twoFactorSecretRepository.findByUserId(USER_ID)).thenReturn(Optional.of(secret));

            assertThatThrownBy(() -> twoFactorService.verifyCode(USER_ID, "000000"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.TWO_FACTOR_INVALID));
        }
    }

    @Nested
    @DisplayName("backup codes")
    class BackupCodeTests {

        @Test
        @DisplayName("valid backup code is consumed and removed")
        void verifyCode_validBackupCode_consumed() {
            String plainCode = "TESTBACKUPCODE1";
            String hashedCode = realPasswordEncoder.encode(plainCode);

            TwoFactorSecret secret = TwoFactorSecret.builder()
                .id(UUID.randomUUID())
                .userId(USER_ID)
                .secret("JBSWY3DPEHPK3PXP")
                .enabled(true)
                .backupCodes(new ArrayList<>(List.of(hashedCode)))
                .build();

            when(twoFactorSecretRepository.findByUserId(USER_ID)).thenReturn(Optional.of(secret));
            when(passwordEncoder.matches(plainCode, hashedCode))
                .thenAnswer(inv -> realPasswordEncoder.matches(inv.getArgument(0), inv.getArgument(1)));
            when(twoFactorSecretRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            assertThatNoException().isThrownBy(() -> twoFactorService.verifyCode(USER_ID, plainCode));

            ArgumentCaptor<TwoFactorSecret> captor = ArgumentCaptor.forClass(TwoFactorSecret.class);
            verify(twoFactorSecretRepository).save(captor.capture());
            assertThat(captor.getValue().getBackupCodes()).isEmpty();
        }

        @Test
        @DisplayName("regenerateBackupCodes returns 8 new codes")
        void regenerateBackupCodes_enabled_returnsEightCodes() {
            TwoFactorSecret secret = TwoFactorSecret.builder()
                .id(UUID.randomUUID())
                .userId(USER_ID)
                .secret("JBSWY3DPEHPK3PXP")
                .enabled(true)
                .backupCodes(new ArrayList<>())
                .build();
            when(twoFactorSecretRepository.findByUserId(USER_ID)).thenReturn(Optional.of(secret));
            when(passwordEncoder.encode(anyString())).thenReturn("hashed");
            when(twoFactorSecretRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            List<String> codes = twoFactorService.regenerateBackupCodes(USER_ID);

            assertThat(codes).hasSize(8);
            assertThat(codes).allMatch(c -> c.length() == 10);
        }
    }
}
