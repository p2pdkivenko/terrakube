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
        return isMfaVerifiedAfter(userEmail, 0);
    }

    /**
     * Check if a user has a valid MFA verification session that was created
     * after the given token issued-at time. This ensures a new login (new token)
     * requires fresh MFA verification even if an old session exists.
     *
     * @param userEmail the email of the user to check
     * @param tokenIssuedAtSeconds the JWT 'iat' claim in epoch seconds (0 to skip check)
     * @return true if the user has a valid MFA session verified after the token was issued
     */
    public boolean isMfaVerifiedAfter(String userEmail, long tokenIssuedAtSeconds) {
        if (userEmail == null || userEmail.isBlank()) {
            return false;
        }
        String key = KEY_PREFIX + userEmail;
        Object value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            return false;
        }
        if (tokenIssuedAtSeconds <= 0) {
            return true;
        }
        long verifiedAtMillis = ((Number) value).longValue();
        long tokenIssuedAtMillis = tokenIssuedAtSeconds * 1000;
        return verifiedAtMillis >= tokenIssuedAtMillis;
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
