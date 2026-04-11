package com.facebook.auth.controller;

import com.facebook.auth.model.entity.Role;
import com.facebook.auth.model.entity.Session;
import com.facebook.auth.model.entity.User;
import com.facebook.auth.repository.SessionRepository;
import com.facebook.auth.repository.UserRepository;
import com.facebook.auth.security.JwtTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("SessionController Integration Tests")
class SessionControllerIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
        .withDatabaseName("authdb_session_test")
        .withUsername("authuser")
        .withPassword("authpass");

    @Container
    @SuppressWarnings("resource")
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
        .withExposedPorts(6379)
        .withCommand("redis-server", "--requirepass", "redispass");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        registry.add("spring.data.redis.password", () -> "redispass");
        registry.add("app.jwt.secret", () -> "session-integration-test-secret-key-must-be-256-bits-padding-here-x");
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private SessionRepository sessionRepository;
    @Autowired private JwtTokenProvider jwtTokenProvider;
    @Autowired private PasswordEncoder passwordEncoder;

    private User testUser;
    private String accessToken;
    private Session testSession;

    @BeforeEach
    void setUp() {
        sessionRepository.deleteAll();
        userRepository.deleteAll();

        Role userRole = Role.builder().name("USER").description("Default").build();
        testUser = User.builder()
            .email("session-test@facebook.com")
            .username("sessiontestuser")
            .passwordHash(passwordEncoder.encode("Password@123"))
            .emailVerified(true)
            .accountLocked(false)
            .roles(Set.of(userRole))
            .build();
        testUser = userRepository.save(testUser);

        accessToken = jwtTokenProvider.generateAccessToken(
            testUser.getId(), testUser.getEmail(),
            Set.of("USER"), Set.of("api:read", "session:read:own", "session:delete:own")
        );

        testSession = sessionRepository.save(Session.builder()
            .userId(testUser.getId())
            .token("test-refresh-token-" + System.currentTimeMillis())
            .ipAddress("127.0.0.1")
            .userAgent("TestBrowser/1.0")
            .expiresAt(Instant.now().plusSeconds(86400))
            .lastAccessedAt(Instant.now())
            .revoked(false)
            .build());
    }

    @Test
    @DisplayName("GET /api/v1/sessions - returns active sessions for authenticated user")
    void getSessions_authenticated_returnsActiveSessions() throws Exception {
        mockMvc.perform(get("/api/v1/sessions")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray())
            .andExpect(jsonPath("$[0].id").isNotEmpty())
            .andExpect(jsonPath("$[0].ip_address").value("127.0.0.1"));
    }

    @Test
    @DisplayName("GET /api/v1/sessions - returns 401 without auth token")
    void getSessions_unauthenticated_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/sessions"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("DELETE /api/v1/sessions/{id} - revokes specific session")
    void revokeSession_ownSession_returns200() throws Exception {
        mockMvc.perform(delete("/api/v1/sessions/" + testSession.getId())
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").isNotEmpty());

        Session revokedSession = sessionRepository.findById(testSession.getId()).orElseThrow();
        assertThat(revokedSession.isRevoked()).isTrue();
    }

    @Test
    @DisplayName("DELETE /api/v1/sessions - revokes all sessions")
    void revokeAllSessions_authenticated_returns200() throws Exception {
        // Create additional sessions
        sessionRepository.save(Session.builder()
            .userId(testUser.getId())
            .token("another-token-" + System.currentTimeMillis())
            .ipAddress("192.168.1.1")
            .expiresAt(Instant.now().plusSeconds(86400))
            .revoked(false)
            .build());

        mockMvc.perform(delete("/api/v1/sessions")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk());

        long activeSessions = sessionRepository.findActiveSessionsByUserId(testUser.getId(), Instant.now()).size();
        assertThat(activeSessions).isZero();
    }
}
