package com.facebook.auth.repository;

import com.facebook.auth.model.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
@DisplayName("UserRepository")
class UserRepositoryTest {

    @Autowired private TestEntityManager entityManager;
    @Autowired private UserRepository userRepository;

    private User savedUser;

    @BeforeEach
    void setUp() {
        User user = User.builder()
            .email("repo-test@facebook.com")
            .username("repotestuser")
            .passwordHash("$2a$12$hashedpassword")
            .displayName("Repo Test User")
            .emailVerified(false)
            .accountLocked(false)
            .failedLoginAttempts(0)
            .emailVerificationToken("verification-token-123")
            .build();

        savedUser = entityManager.persistAndFlush(user);
    }

    @Test
    @DisplayName("findByEmail returns user for existing email")
    void findByEmail_existingEmail_returnsUser() {
        Optional<User> result = userRepository.findByEmail("repo-test@facebook.com");

        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("repo-test@facebook.com");
        assertThat(result.get().getUsername()).isEqualTo("repotestuser");
    }

    @Test
    @DisplayName("findByEmail returns empty for nonexistent email")
    void findByEmail_nonexistentEmail_returnsEmpty() {
        Optional<User> result = userRepository.findByEmail("nobody@facebook.com");

        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("findByUsername returns user for existing username")
    void findByUsername_existingUsername_returnsUser() {
        Optional<User> result = userRepository.findByUsername("repotestuser");

        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedUser.getId());
    }

    @Test
    @DisplayName("existsByEmail returns true for existing email")
    void existsByEmail_existing_returnsTrue() {
        assertThat(userRepository.existsByEmail("repo-test@facebook.com")).isTrue();
    }

    @Test
    @DisplayName("existsByEmail returns false for nonexistent email")
    void existsByEmail_nonexistent_returnsFalse() {
        assertThat(userRepository.existsByEmail("nobody@facebook.com")).isFalse();
    }

    @Test
    @DisplayName("existsByUsername returns true for existing username")
    void existsByUsername_existing_returnsTrue() {
        assertThat(userRepository.existsByUsername("repotestuser")).isTrue();
    }

    @Test
    @DisplayName("findByEmailVerificationToken returns user for valid token")
    void findByEmailVerificationToken_validToken_returnsUser() {
        Optional<User> result = userRepository.findByEmailVerificationToken("verification-token-123");

        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedUser.getId());
    }

    @Test
    @DisplayName("findByEmailVerificationToken returns empty for invalid token")
    void findByEmailVerificationToken_invalidToken_returnsEmpty() {
        assertThat(userRepository.findByEmailVerificationToken("bad-token")).isEmpty();
    }

    @Test
    @DisplayName("incrementFailedLoginAttempts increases counter")
    void incrementFailedLoginAttempts_incrementsCounter() {
        assertThat(savedUser.getFailedLoginAttempts()).isZero();

        userRepository.incrementFailedLoginAttempts(savedUser.getId());
        entityManager.clear();

        User updated = userRepository.findById(savedUser.getId()).orElseThrow();
        assertThat(updated.getFailedLoginAttempts()).isEqualTo(1);
    }

    @Test
    @DisplayName("resetFailedLoginAttempts sets counter to zero")
    void resetFailedLoginAttempts_resetsCounter() {
        savedUser.setFailedLoginAttempts(3);
        entityManager.persistAndFlush(savedUser);

        userRepository.resetFailedLoginAttempts(savedUser.getId());
        entityManager.clear();

        User updated = userRepository.findById(savedUser.getId()).orElseThrow();
        assertThat(updated.getFailedLoginAttempts()).isZero();
    }

    @Test
    @DisplayName("save persists user with generated UUID")
    void save_newUser_generatesUuid() {
        User newUser = User.builder()
            .email("new@facebook.com")
            .username("newuser")
            .passwordHash("hash")
            .emailVerified(false)
            .accountLocked(false)
            .build();

        User persisted = userRepository.save(newUser);

        assertThat(persisted.getId()).isNotNull();
        assertThat(persisted.getCreatedAt()).isNotNull();
    }
}
