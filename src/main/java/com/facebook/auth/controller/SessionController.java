package com.facebook.auth.controller;

import com.facebook.auth.model.entity.Session;
import com.facebook.auth.service.SessionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/sessions")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Sessions", description = "Session management endpoints")
@SecurityRequirement(name = "bearerAuth")
public class SessionController {

    private final SessionService sessionService;

    @GetMapping
    @Operation(summary = "List all active sessions for current user")
    public ResponseEntity<List<SessionSummary>> getActiveSessions(@AuthenticationPrincipal UUID userId) {
        List<Session> sessions = sessionService.getActiveSessions(userId);
        List<SessionSummary> summaries = sessions.stream()
            .map(SessionSummary::from)
            .toList();
        return ResponseEntity.ok(summaries);
    }

    @DeleteMapping("/{sessionId}")
    @Operation(summary = "Revoke a specific session")
    public ResponseEntity<Map<String, String>> revokeSession(
            @PathVariable UUID sessionId,
            @AuthenticationPrincipal UUID userId) {

        sessionService.revokeSession(sessionId, userId);
        return ResponseEntity.ok(Map.of("message", "Session revoked successfully"));
    }

    @DeleteMapping
    @Operation(summary = "Revoke all sessions for current user")
    public ResponseEntity<Map<String, String>> revokeAllSessions(@AuthenticationPrincipal UUID userId) {
        sessionService.revokeAllSessions(userId);
        return ResponseEntity.ok(Map.of("message", "All sessions revoked successfully"));
    }

    public record SessionSummary(
        UUID id,
        String ipAddress,
        String userAgent,
        Instant createdAt,
        Instant lastAccessedAt,
        Instant expiresAt
    ) {
        public static SessionSummary from(Session session) {
            return new SessionSummary(
                session.getId(),
                session.getIpAddress(),
                session.getUserAgent(),
                session.getCreatedAt(),
                session.getLastAccessedAt(),
                session.getExpiresAt()
            );
        }
    }
}
