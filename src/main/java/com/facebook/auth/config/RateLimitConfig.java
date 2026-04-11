package com.facebook.auth.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Configuration
public class RateLimitConfig {

    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> apiBuckets = new ConcurrentHashMap<>();

    /**
     * Login rate limit: 10 attempts per minute per IP address.
     */
    public Bucket getLoginBucket(String ipAddress) {
        return loginBuckets.computeIfAbsent(ipAddress, key ->
            Bucket.builder()
                .addLimit(Bandwidth.builder()
                    .capacity(10)
                    .refillIntervally(10, Duration.ofMinutes(1))
                    .build())
                .build()
        );
    }

    /**
     * API rate limit: 100 requests per minute per user/IP.
     */
    public Bucket getApiBucket(String identifier) {
        return apiBuckets.computeIfAbsent(identifier, key ->
            Bucket.builder()
                .addLimit(Bandwidth.builder()
                    .capacity(100)
                    .refillIntervally(100, Duration.ofMinutes(1))
                    .build())
                .build()
        );
    }
}
