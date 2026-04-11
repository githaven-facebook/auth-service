package com.facebook.auth.model.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "two_factor_secrets", indexes = {
    @Index(name = "idx_2fa_user_id", columnList = "user_id", unique = true)
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TwoFactorSecret {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "user_id", unique = true, nullable = false)
    private UUID userId;

    @Column(name = "secret", nullable = false, length = 64)
    private String secret;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "two_factor_backup_codes",
        joinColumns = @JoinColumn(name = "two_factor_secret_id"))
    @Column(name = "backup_code_hash")
    private List<String> backupCodes;

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private boolean enabled = false;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;
}
