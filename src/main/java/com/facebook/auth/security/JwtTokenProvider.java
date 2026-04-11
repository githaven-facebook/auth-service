package com.facebook.auth.security;

import com.facebook.auth.config.JwtConfig;
import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMISSIONS = "permissions";
    private static final String CLAIM_TYPE = "type";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    private final JwtConfig jwtConfig;

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(UUID userId, String email, Set<String> roles, Set<String> permissions) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(jwtConfig.getAccessTokenExpirySeconds());

        return Jwts.builder()
            .id(UUID.randomUUID().toString())
            .subject(userId.toString())
            .issuer(jwtConfig.getIssuer())
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            .claim("email", email)
            .claim(CLAIM_ROLES, roles)
            .claim(CLAIM_PERMISSIONS, permissions)
            .claim(CLAIM_TYPE, TYPE_ACCESS)
            .signWith(getSigningKey(), Jwts.SIG.HS256)
            .compact();
    }

    public String generateRefreshToken(UUID userId) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(jwtConfig.getRefreshTokenExpirySeconds());

        return Jwts.builder()
            .id(UUID.randomUUID().toString())
            .subject(userId.toString())
            .issuer(jwtConfig.getIssuer())
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            .claim(CLAIM_TYPE, TYPE_REFRESH)
            .signWith(getSigningKey(), Jwts.SIG.HS256)
            .compact();
    }

    public Claims validateAndExtractClaims(String token) {
        try {
            return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        } catch (ExpiredJwtException e) {
            log.debug("JWT token expired: {}", e.getMessage());
            throw new AuthException(ErrorCode.TOKEN_EXPIRED);
        } catch (JwtException e) {
            log.debug("JWT token invalid: {}", e.getMessage());
            throw new AuthException(ErrorCode.TOKEN_INVALID);
        }
    }

    public UUID extractUserId(String token) {
        Claims claims = validateAndExtractClaims(token);
        return UUID.fromString(claims.getSubject());
    }

    public String extractTokenId(String token) {
        Claims claims = validateAndExtractClaims(token);
        return claims.getId();
    }

    @SuppressWarnings("unchecked")
    public Set<String> extractRoles(String token) {
        Claims claims = validateAndExtractClaims(token);
        Object rolesObj = claims.get(CLAIM_ROLES);
        if (rolesObj instanceof List<?> roleList) {
            return new HashSet<>((List<String>) roleList);
        }
        return Collections.emptySet();
    }

    @SuppressWarnings("unchecked")
    public Set<String> extractPermissions(String token) {
        Claims claims = validateAndExtractClaims(token);
        Object permsObj = claims.get(CLAIM_PERMISSIONS);
        if (permsObj instanceof List<?> permList) {
            return new HashSet<>((List<String>) permList);
        }
        return Collections.emptySet();
    }

    public boolean isAccessToken(String token) {
        Claims claims = validateAndExtractClaims(token);
        return TYPE_ACCESS.equals(claims.get(CLAIM_TYPE));
    }

    public boolean isRefreshToken(String token) {
        Claims claims = validateAndExtractClaims(token);
        return TYPE_REFRESH.equals(claims.get(CLAIM_TYPE));
    }

    public long getAccessTokenExpirySeconds() {
        return jwtConfig.getAccessTokenExpirySeconds();
    }
}
