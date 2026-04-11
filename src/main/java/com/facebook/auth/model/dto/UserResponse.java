package com.facebook.auth.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record UserResponse(
    UUID id,
    String email,
    String username,

    @JsonProperty("display_name")
    String displayName,

    @JsonProperty("email_verified")
    boolean emailVerified,

    @JsonProperty("account_locked")
    boolean accountLocked,

    @JsonProperty("two_factor_enabled")
    boolean twoFactorEnabled,

    Set<String> roles,

    @JsonProperty("last_login_at")
    Instant lastLoginAt,

    @JsonProperty("created_at")
    Instant createdAt
) {}
