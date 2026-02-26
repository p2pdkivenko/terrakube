package io.terrakube.api.plugin.mfa.session;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Service for managing MFA session verification state in Redis.
 * Replaces the in-memory ConcurrentHashMap storage with distributed Redis storage.
 */
@Slf4j
@Service
public class MfaSessionService {

    private static final String KEY_PREFIX = "mfa:session:";

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${io.terrakube.mfa.session.ttl:28800}")
    private long sessionTtlSeconds;

    public MfaSessionService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Mark a user's MFA as verified by storing the verification timestamp in Redis.
     * The key will automatically expire based on the configured TTL.
     *
     * @param userEmail the email of the user who completed MFA verification
     */
    public void markMfaVerified(String userEmail) {
        if (userEmail != null && !userEmail.isBlank()) {
            String key = KEY_PREFIX + userEmail;
            redisTemplate.opsForValue().set(key, System.currentTimeMillis(), sessionTtlSeconds, TimeUnit.SECONDS);
            log.info("MFA session marked verified for user: {}", userEmail);
        }
    }

    /**
     * Check if a user has a valid MFA verification session.
     * Returns true if the key exists (TTL is handled by Redis automatically).
     *
     * @param userEmail the email of the user to check
     * @return true if the user has a valid MFA verification session, false otherwise
     */
    public boolean isMfaVerified(String userEmail) {
        if (userEmail == null || userEmail.isBlank()) {
            return false;
        }
        String key = KEY_PREFIX + userEmail;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * Clear a user's MFA verification session.
     * This can be used for logout or admin-initiated session reset.
     *
     * @param userEmail the email of the user whose session should be cleared
     */
    public void clearMfaSession(String userEmail) {
        if (userEmail != null && !userEmail.isBlank()) {
            String key = KEY_PREFIX + userEmail;
            redisTemplate.delete(key);
            log.info("MFA session cleared for user: {}", userEmail);
        }
    }
}
