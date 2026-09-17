package io.hexlet.cv.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.hexlet.cv.model.RefreshToken;
import io.hexlet.cv.model.User;
import io.hexlet.cv.model.enums.RoleType;
import io.hexlet.cv.repository.RefreshTokenRepository;
import io.hexlet.cv.repository.UserRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class RefreshTokenCleanupJobTest {

    @Autowired
    private RefreshTokenCleanupJob cleanupJob;

    @Autowired
    private RefreshTokenRepository repository;

    @Autowired
    private UserRepository userRepository;

    private Long userId;

    @BeforeEach
    void setUp() {
        repository.deleteAll();

        var user = new User();
        user.setEmail("cleanup-job-test@example.com");
        user.setEncryptedPassword("irrelevant-hash");
        user.setFirstName("firstName");
        user.setLastName("lastName");
        user.setRole(RoleType.CANDIDATE);
        userId = userRepository.save(user).getId();
    }

    @Test
    void purgeExpiredRemovesOnlyExpiredRows() {

        var expired = RefreshToken.builder()
                .jti(UUID.randomUUID())
                .userId(userId)
                .familyId(UUID.randomUUID())
                .issuedAt(Instant.now().minusSeconds(3600))
                .expiresAt(Instant.now().minusSeconds(60))
                .build();
        repository.save(expired);

        var active = RefreshToken.builder()
                .jti(UUID.randomUUID())
                .userId(userId)
                .familyId(UUID.randomUUID())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        repository.save(active);

        cleanupJob.purgeExpired();

        assertThat(repository.existsById(expired.getJti())).isFalse();
        assertThat(repository.existsById(active.getJti())).isTrue();
    }
}
