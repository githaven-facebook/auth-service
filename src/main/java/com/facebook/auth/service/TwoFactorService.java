package com.facebook.auth.service;

import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.dto.TwoFactorSetupResponse;
import com.facebook.auth.model.entity.TwoFactorSecret;
import com.facebook.auth.repository.TwoFactorSecretRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class TwoFactorService {

    private static final String TOTP_ALGORITHM = "HmacSHA1";
    private static final int TOTP_DIGITS = 6;
    private static final int TOTP_PERIOD = 30;
    private static final int TOTP_WINDOW = 1;
    private static final int BACKUP_CODE_COUNT = 8;
    private static final int BACKUP_CODE_LENGTH = 10;

    private final TwoFactorSecretRepository twoFactorSecretRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public TwoFactorSetupResponse setupTwoFactor(UUID userId, String email) {
        if (twoFactorSecretRepository.existsByUserIdAndEnabledTrue(userId)) {
            throw new AuthException(ErrorCode.TWO_FACTOR_ALREADY_ENABLED);
        }

        String secret = generateSecret();
        List<String> plainBackupCodes = generatePlainBackupCodes();
        List<String> hashedBackupCodes = plainBackupCodes.stream()
            .map(passwordEncoder::encode)
            .toList();

        TwoFactorSecret twoFactorSecret = twoFactorSecretRepository.findByUserId(userId)
            .orElse(TwoFactorSecret.builder().userId(userId).build());

        twoFactorSecret.setSecret(secret);
        twoFactorSecret.setBackupCodes(hashedBackupCodes);
        twoFactorSecret.setEnabled(false);
        twoFactorSecretRepository.save(twoFactorSecret);

        String qrCodeUri = buildQrCodeUri(email, secret);

        return new TwoFactorSetupResponse(secret, qrCodeUri, null, plainBackupCodes);
    }

    @Transactional
    public void enableTwoFactor(UUID userId, String code) {
        TwoFactorSecret twoFactorSecret = twoFactorSecretRepository.findByUserId(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.TWO_FACTOR_NOT_ENABLED));

        if (!verifyTotpCode(twoFactorSecret.getSecret(), code)) {
            throw new AuthException(ErrorCode.TWO_FACTOR_INVALID);
        }

        twoFactorSecret.setEnabled(true);
        twoFactorSecret.setVerifiedAt(Instant.now());
        twoFactorSecretRepository.save(twoFactorSecret);
        log.info("2FA enabled for user: {}", userId);
    }

    @Transactional
    public void verifyCode(UUID userId, String code) {
        TwoFactorSecret twoFactorSecret = twoFactorSecretRepository.findByUserId(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.TWO_FACTOR_NOT_ENABLED));

        if (!twoFactorSecret.isEnabled()) {
            throw new AuthException(ErrorCode.TWO_FACTOR_NOT_ENABLED);
        }

        // Try TOTP first, then backup codes
        if (!verifyTotpCode(twoFactorSecret.getSecret(), code)) {
            if (!verifyAndConsumeBackupCode(twoFactorSecret, code)) {
                throw new AuthException(ErrorCode.TWO_FACTOR_INVALID);
            }
        }
    }

    @Transactional
    public void disableTwoFactor(UUID userId, String code) {
        TwoFactorSecret twoFactorSecret = twoFactorSecretRepository.findByUserId(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.TWO_FACTOR_NOT_ENABLED));

        if (!twoFactorSecret.isEnabled()) {
            throw new AuthException(ErrorCode.TWO_FACTOR_NOT_ENABLED);
        }

        if (!verifyTotpCode(twoFactorSecret.getSecret(), code)) {
            throw new AuthException(ErrorCode.TWO_FACTOR_INVALID);
        }

        twoFactorSecretRepository.delete(twoFactorSecret);
        log.info("2FA disabled for user: {}", userId);
    }

    @Transactional
    public List<String> regenerateBackupCodes(UUID userId) {
        TwoFactorSecret twoFactorSecret = twoFactorSecretRepository.findByUserId(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.TWO_FACTOR_NOT_ENABLED));

        if (!twoFactorSecret.isEnabled()) {
            throw new AuthException(ErrorCode.TWO_FACTOR_NOT_ENABLED);
        }

        List<String> plainBackupCodes = generatePlainBackupCodes();
        List<String> hashedBackupCodes = plainBackupCodes.stream()
            .map(passwordEncoder::encode)
            .toList();

        twoFactorSecret.setBackupCodes(hashedBackupCodes);
        twoFactorSecretRepository.save(twoFactorSecret);

        return plainBackupCodes;
    }

    public boolean isTwoFactorEnabled(UUID userId) {
        return twoFactorSecretRepository.existsByUserIdAndEnabledTrue(userId);
    }

    private boolean verifyTotpCode(String secret, String code) {
        if (code == null || code.length() != TOTP_DIGITS) {
            return false;
        }

        long currentTimeStep = Instant.now().getEpochSecond() / TOTP_PERIOD;

        for (int i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
            String expectedCode = generateTotpCode(secret, currentTimeStep + i);
            if (expectedCode.equals(code)) {
                return true;
            }
        }
        return false;
    }

    private String generateTotpCode(String secret, long timeStep) {
        try {
            Base32 base32 = new Base32();
            byte[] keyBytes = base32.decode(secret.toUpperCase());
            byte[] timeBytes = ByteBuffer.allocate(8).putLong(timeStep).array();

            Mac mac = Mac.getInstance(TOTP_ALGORITHM);
            mac.init(new SecretKeySpec(keyBytes, TOTP_ALGORITHM));
            byte[] hash = mac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int otp = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);

            otp = otp % (int) Math.pow(10, TOTP_DIGITS);
            return String.format("%0" + TOTP_DIGITS + "d", otp);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Failed to generate TOTP code", e);
        }
    }

    private boolean verifyAndConsumeBackupCode(TwoFactorSecret twoFactorSecret, String code) {
        List<String> backupCodes = new ArrayList<>(twoFactorSecret.getBackupCodes());

        for (int i = 0; i < backupCodes.size(); i++) {
            if (passwordEncoder.matches(code, backupCodes.get(i))) {
                backupCodes.remove(i);
                twoFactorSecret.setBackupCodes(backupCodes);
                twoFactorSecretRepository.save(twoFactorSecret);
                log.info("Backup code used for user: {}", twoFactorSecret.getUserId());
                return true;
            }
        }
        return false;
    }

    private String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte[] secretBytes = new byte[20];
        random.nextBytes(secretBytes);
        return new Base32().encodeToString(secretBytes);
    }

    private List<String> generatePlainBackupCodes() {
        SecureRandom random = new SecureRandom();
        List<String> codes = new ArrayList<>(BACKUP_CODE_COUNT);
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        for (int i = 0; i < BACKUP_CODE_COUNT; i++) {
            StringBuilder code = new StringBuilder(BACKUP_CODE_LENGTH);
            for (int j = 0; j < BACKUP_CODE_LENGTH; j++) {
                code.append(chars.charAt(random.nextInt(chars.length())));
            }
            codes.add(code.toString());
        }
        return codes;
    }

    private String buildQrCodeUri(String email, String secret) {
        String issuer = "FacebookAuth";
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
            issuer, email, secret, issuer
        );
    }
}
