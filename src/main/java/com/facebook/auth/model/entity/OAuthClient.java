package com.facebook.auth.model.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "oauth_clients")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuthClient {

    @Id
    @Column(name = "client_id", length = 100)
    private String clientId;

    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @Column(name = "client_name", nullable = false, length = 100)
    private String clientName;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_redirect_uris",
        joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uri")
    private Set<String> redirectUris;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_grant_types",
        joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "grant_type")
    private Set<String> grantTypes;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_scopes",
        joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope")
    private Set<String> scopes;

    @Column(name = "access_token_ttl_seconds")
    @Builder.Default
    private int accessTokenTtlSeconds = 900;

    @Column(name = "refresh_token_ttl_seconds")
    @Builder.Default
    private int refreshTokenTtlSeconds = 604800;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private Instant updatedAt;
}
