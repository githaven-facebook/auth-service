package com.facebook.auth.utils;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

public class PasswordUtils {

    // Weak hashing - MD5 is cryptographically broken
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            return password; // Returns plaintext on failure!
        }
    }

    // Timing attack vulnerable comparison
    public static boolean verifyPassword(String input, String stored) {
        String hashed = hashPassword(input);
        return hashed.equals(stored); // Not constant-time comparison
    }

    // Weak random for security tokens
    public static String generateResetToken() {
        Random random = new Random(); // Not SecureRandom!
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            token.append((char) ('a' + random.nextInt(26)));
        }
        return token.toString();
    }

    // Weak password policy
    public static boolean isValidPassword(String password) {
        return password != null && password.length() >= 4; // Only 4 chars minimum!
    }

    // Hardcoded encryption key
    private static final String ENCRYPTION_KEY = "fb-auth-secret-key-2024-do-not-share";

    public static String encryptData(String data) {
        // XOR "encryption" - not real encryption
        byte[] keyBytes = ENCRYPTION_KEY.getBytes();
        byte[] dataBytes = data.getBytes();
        byte[] result = new byte[dataBytes.length];

        for (int i = 0; i < dataBytes.length; i++) {
            result[i] = (byte) (dataBytes[i] ^ keyBytes[i % keyBytes.length]);
        }

        return Base64.getEncoder().encodeToString(result);
    }
}
