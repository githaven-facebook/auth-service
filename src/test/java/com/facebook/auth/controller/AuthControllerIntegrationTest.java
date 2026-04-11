package com.facebook.auth.controller;

import com.facebook.auth.model.dto.LoginRequest;
import com.facebook.auth.model.dto.RegisterRequest;
import com.facebook.auth.model.dto.TokenResponse;
import com.facebook.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("AuthController Integration Tests")
class AuthControllerIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
        .withDatabaseName("authdb_test")
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
        registry.add("spring.flyway.locations", () -> "classpath:db/migration");
        registry.add("app.jwt.secret", () -> "integration-test-secret-key-must-be-at-least-256-bits-long-padding-here");
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;

    private static final String TEST_EMAIL = "integration@facebook.com";
    private static final String TEST_USERNAME = "integrationuser";
    private static final String TEST_PASSWORD = "IntTest@123";

    @Test
    @Order(1)
    @DisplayName("POST /api/v1/auth/register - creates new user account")
    void register_validRequest_returns201() throws Exception {
        RegisterRequest request = new RegisterRequest(TEST_EMAIL, TEST_USERNAME, TEST_PASSWORD, "Integration User");

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.email").value(TEST_EMAIL))
            .andExpect(jsonPath("$.username").value(TEST_USERNAME))
            .andExpect(jsonPath("$.email_verified").value(false));

        assertThat(userRepository.existsByEmail(TEST_EMAIL)).isTrue();
    }

    @Test
    @Order(2)
    @DisplayName("POST /api/v1/auth/register - returns 409 for duplicate email")
    void register_duplicateEmail_returns409() throws Exception {
        RegisterRequest request = new RegisterRequest(TEST_EMAIL, "anotheruser", TEST_PASSWORD, null);

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.errorCode").value("USER_002"));
    }

    @Test
    @Order(3)
    @DisplayName("POST /api/v1/auth/login - returns 403 before email verification")
    void login_emailNotVerified_returns403() throws Exception {
        LoginRequest request = new LoginRequest(TEST_EMAIL, TEST_PASSWORD, null);

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.errorCode").value("AUTH_003"));
    }

    @Test
    @Order(4)
    @DisplayName("POST /api/v1/auth/login - succeeds after email verification")
    void login_afterVerification_returnsTokens() throws Exception {
        // Manually verify email for test
        userRepository.findByEmail(TEST_EMAIL).ifPresent(user -> {
            user.setEmailVerified(true);
            userRepository.save(user);
        });

        LoginRequest request = new LoginRequest(TEST_EMAIL, TEST_PASSWORD, null);

        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isNotEmpty())
            .andExpect(jsonPath("$.refresh_token").isNotEmpty())
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andReturn();

        String responseJson = result.getResponse().getContentAsString();
        TokenResponse tokenResponse = objectMapper.readValue(responseJson, TokenResponse.class);
        assertThat(tokenResponse.accessToken()).isNotBlank();
        assertThat(tokenResponse.refreshToken()).isNotBlank();
    }

    @Test
    @Order(5)
    @DisplayName("POST /api/v1/auth/login - returns 401 for wrong password")
    void login_wrongPassword_returns401() throws Exception {
        LoginRequest request = new LoginRequest(TEST_EMAIL, "WrongPass@123", null);

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.errorCode").value("AUTH_001"));
    }

    @Test
    @Order(6)
    @DisplayName("POST /api/v1/auth/register - returns 400 for invalid email")
    void register_invalidEmail_returns400() throws Exception {
        RegisterRequest request = new RegisterRequest("not-an-email", "validuser", TEST_PASSWORD, null);

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errorCode").value("GEN_001"));
    }

    @Test
    @Order(7)
    @DisplayName("POST /api/v1/auth/forgot-password - returns 200 regardless of email existence")
    void forgotPassword_anyEmail_returns200() throws Exception {
        mockMvc.perform(post("/api/v1/auth/forgot-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"nonexistent@facebook.com\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").isNotEmpty());
    }
}
