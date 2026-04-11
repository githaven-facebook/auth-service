package com.facebook.auth.service;

import com.facebook.auth.config.JwtConfig;
import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private static final String BLACKLIST_PREFIX = "token:blacklist:";
    private static final String REFRESH_PREFIX = "token:refresh:";

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtConfig jwtConfig;
    private final RedisTemplate<String, String> redisTemplate;

    public String generateAccessToken(UUID userId, String email, Set<String> roles, Set<String> permissions) {
        return jwtTokenProvider.generateAccessToken(userId, email, roles, permissions);
    }

    public String generateRefreshToken(UUID userId) {
        String refreshToken = jwtTokenProvider.generateRefreshToken(userId);
        String tokenId = jwtTokenProvider.extractTokenId(refreshToken);

        redisTemplate.opsForValue().set(
            REFRESH_PREFIX + tokenId,
            userId.toString(),
            jwtConfig.getRefreshTokenExpirySeconds(),
            TimeUnit.SECONDS
        );

        return refreshToken;
    }

    public UUID validateRefreshToken(String refreshToken) {
        if (!jwtTokenProvider.isRefreshToken(refreshToken)) {
            throw new AuthException(ErrorCode.REFRESH_TOKEN_INVALID);
        }

        if (isTokenBlacklisted(refreshToken)) {
            throw new AuthException(ErrorCode.TOKEN_REVOKED);
        }

        String tokenId = jwtTokenProvider.extractTokenId(refreshToken);
        String userIdStr = redisTemplate.opsForValue().get(REFRESH_PREFIX + tokenId);

        if (userIdStr == null) {
            throw new AuthException(ErrorCode.REFRESH_TOKEN_INVALID);
        }

        return jwtTokenProvider.extractUserId(refreshToken);
    }

    public void revokeToken(String token) {
        try {
            String tokenId = jwtTokenProvider.extractTokenId(token);
            boolean isRefresh = jwtTokenProvider.isRefreshToken(token);

            long ttl = isRefresh
                ? jwtConfig.getRefreshTokenExpirySeconds()
                : jwtConfig.getAccessTokenExpirySeconds();

            redisTemplate.opsForValue().set(
                BLACKLIST_PREFIX + tokenId,
                "revoked",
                ttl,
                TimeUnit.SECONDS
            );

            if (isRefresh) {
                redisTemplate.delete(REFRESH_PREFIX + tokenId);
            }
        } catch (AuthException e) {
            log.debug("Could not revoke token - may already be expired: {}", e.getMessage());
        }
    }

    public boolean isTokenBlacklisted(String token) {
        try {
            String tokenId = jwtTokenProvider.extractTokenId(token);
            return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + tokenId));
        } catch (AuthException e) {
            return true;
        }
    }

    public void revokeAllUserTokens(UUID userId) {
        String pattern = REFRESH_PREFIX + "*";
        Set<String> keys = redisTemplate.keys(pattern);
        if (keys != null) {
            for (String key : keys) {
                String storedUserId = redisTemplate.opsForValue().get(key);
                if (userId.toString().equals(storedUserId)) {
                    redisTemplate.delete(key);
                }
            }
        }
    }
}
