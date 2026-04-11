package com.facebook.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

@Configuration
@ConfigurationProperties(prefix = "app.jwt")
@Validated
@Getter
@Setter
public class JwtConfig {

    @NotBlank
    private String secret;

    @Min(60)
    private long accessTokenExpirySeconds = 900; // 15 minutes

    @Min(3600)
    private long refreshTokenExpirySeconds = 604800; // 7 days

    @NotBlank
    private String issuer = "https://auth.facebook.com";
}
