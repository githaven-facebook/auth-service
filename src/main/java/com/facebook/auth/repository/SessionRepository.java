package com.facebook.auth.repository;

import com.facebook.auth.model.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SessionRepository extends JpaRepository<Session, UUID> {

    Optional<Session> findByTokenAndRevokedFalse(String token);

    @Query("SELECT s FROM Session s WHERE s.userId = :userId AND s.revoked = false AND s.expiresAt > :now")
    List<Session> findActiveSessionsByUserId(@Param("userId") UUID userId, @Param("now") Instant now);

    @Modifying
    @Query("UPDATE Session s SET s.revoked = true WHERE s.userId = :userId")
    void revokeAllByUserId(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE Session s SET s.revoked = true WHERE s.userId = :userId AND s.id != :sessionId")
    void revokeOtherSessionsByUserId(@Param("userId") UUID userId, @Param("sessionId") UUID sessionId);

    @Modifying
    @Query("DELETE FROM Session s WHERE s.expiresAt < :threshold AND s.revoked = true")
    int deleteExpiredSessions(@Param("threshold") Instant threshold);

    long countByUserIdAndRevokedFalse(UUID userId);
}
