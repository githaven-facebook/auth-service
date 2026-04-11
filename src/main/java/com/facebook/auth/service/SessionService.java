package com.facebook.auth.service;

import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.entity.Session;
import com.facebook.auth.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

    private static final int MAX_CONCURRENT_SESSIONS = 5;

    private final SessionRepository sessionRepository;

    @Value("${app.session.expiry-seconds:2592000}")
    private long sessionExpirySeconds;

    @Transactional
    public Session createSession(UUID userId, String token, String ipAddress, String userAgent) {
        long activeCount = sessionRepository.countByUserIdAndRevokedFalse(userId);
        if (activeCount >= MAX_CONCURRENT_SESSIONS) {
            List<Session> activeSessions = sessionRepository.findActiveSessionsByUserId(userId, Instant.now());
            if (!activeSessions.isEmpty()) {
                Session oldest = activeSessions.stream()
                    .min((a, b) -> a.getCreatedAt().compareTo(b.getCreatedAt()))
                    .orElseThrow();
                oldest.setRevoked(true);
                sessionRepository.save(oldest);
                log.info("Revoked oldest session {} for user {} due to session limit", oldest.getId(), userId);
            }
        }

        Instant now = Instant.now();
        Session session = Session.builder()
            .userId(userId)
            .token(token)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .expiresAt(now.plusSeconds(sessionExpirySeconds))
            .lastAccessedAt(now)
            .revoked(false)
            .build();

        return sessionRepository.save(session);
    }

    @Transactional
    public Session validateAndRefreshSession(String token) {
        Session session = sessionRepository.findByTokenAndRevokedFalse(token)
            .orElseThrow(() -> new AuthException(ErrorCode.SESSION_NOT_FOUND));

        if (session.getExpiresAt().isBefore(Instant.now())) {
            session.setRevoked(true);
            sessionRepository.save(session);
            throw new AuthException(ErrorCode.SESSION_EXPIRED);
        }

        // Sliding expiration
        session.setLastAccessedAt(Instant.now());
        session.setExpiresAt(Instant.now().plusSeconds(sessionExpirySeconds));
        return sessionRepository.save(session);
    }

    @Transactional
    public void revokeSession(UUID sessionId, UUID userId) {
        Session session = sessionRepository.findById(sessionId)
            .orElseThrow(() -> new AuthException(ErrorCode.SESSION_NOT_FOUND));

        if (!session.getUserId().equals(userId)) {
            throw new AuthException(ErrorCode.INSUFFICIENT_PERMISSIONS);
        }

        session.setRevoked(true);
        sessionRepository.save(session);
        log.info("Session {} revoked for user {}", sessionId, userId);
    }

    @Transactional
    public void revokeAllSessions(UUID userId) {
        sessionRepository.revokeAllByUserId(userId);
        log.info("All sessions revoked for user {}", userId);
    }

    @Transactional(readOnly = true)
    public List<Session> getActiveSessions(UUID userId) {
        return sessionRepository.findActiveSessionsByUserId(userId, Instant.now());
    }

    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupExpiredSessions() {
        Instant threshold = Instant.now().minus(7, ChronoUnit.DAYS);
        int deleted = sessionRepository.deleteExpiredSessions(threshold);
        log.info("Cleaned up {} expired sessions", deleted);
    }
}
