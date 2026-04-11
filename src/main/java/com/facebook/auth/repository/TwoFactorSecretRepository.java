package com.facebook.auth.repository;

import com.facebook.auth.model.entity.TwoFactorSecret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface TwoFactorSecretRepository extends JpaRepository<TwoFactorSecret, UUID> {

    Optional<TwoFactorSecret> findByUserId(UUID userId);

    boolean existsByUserIdAndEnabledTrue(UUID userId);
}
