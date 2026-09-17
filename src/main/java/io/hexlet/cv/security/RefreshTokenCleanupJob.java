package io.hexlet.cv.security;

import java.time.Instant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Просроченные refresh-токены уже отвергаются декодером — строки только занимают место. */
@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenCleanupJob {

    private final RefreshTokenStore store;

    @Scheduled(cron = "${app.security.jwt.cleanup-cron}")
    public void purgeExpired() {
        int removed = store.purgeExpired(Instant.now());
        if (removed > 0) {
            log.info("Purged {} expired refresh tokens", removed);
        }
    }
}
