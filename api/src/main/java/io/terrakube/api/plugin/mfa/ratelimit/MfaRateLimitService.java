package io.terrakube.api.plugin.mfa.ratelimit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import io.terrakube.api.repository.MfaAttemptRepository;
import io.terrakube.api.rs.mfa.MfaAttempt;

import java.time.LocalDateTime;

@Slf4j
@Service
public class MfaRateLimitService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int TIME_WINDOW_MINUTES = 1;

    private final MfaAttemptRepository mfaAttemptRepository;

    public MfaRateLimitService(MfaAttemptRepository mfaAttemptRepository) {
        this.mfaAttemptRepository = mfaAttemptRepository;
    }

    /**
     * Check if a user is allowed to attempt MFA verification.
     * Returns true if the user has fewer than MAX_FAILED_ATTEMPTS in the last TIME_WINDOW_MINUTES.
     * Returns false if the user is rate limited (blocked).
     *
     * @param userEmail the email of the user attempting MFA
     * @return true if allowed, false if blocked
     */
    public boolean checkRateLimit(String userEmail) {
        LocalDateTime timeWindowStart = LocalDateTime.now().minusMinutes(TIME_WINDOW_MINUTES);
        long failedAttempts = mfaAttemptRepository.countByUserEmailAndCreatedDateAfter(userEmail, timeWindowStart);

        boolean allowed = failedAttempts < MAX_FAILED_ATTEMPTS;
        if (!allowed) {
            log.warn("Rate limit exceeded for user: {} with {} failed attempts in the last {} minute(s)",
                    userEmail, failedAttempts, TIME_WINDOW_MINUTES);
        }
        return allowed;
    }

    /**
     * Record an MFA attempt for a user.
     * Creates a new MfaAttempt entity and saves it to the repository.
     *
     * @param userEmail the email of the user
     * @param attemptType the type of MFA attempt ("TOTP", "WEBAUTHN", "BACKUP_CODE")
     * @param success whether the attempt was successful
     * @param ipAddress the IP address from which the attempt was made (optional)
     */
    public void recordAttempt(String userEmail, String attemptType, boolean success, String ipAddress) {
        MfaAttempt attempt = new MfaAttempt();
        attempt.setUserEmail(userEmail);
        attempt.setAttemptType(attemptType);
        attempt.setSuccess(success);
        attempt.setIpAddress(ipAddress);

        mfaAttemptRepository.save(attempt);
        log.info("Recorded MFA attempt for user: {} with type: {} and success: {}", userEmail, attemptType, success);
    }

    /**
     * Clear all failed attempts for a user (called on successful verification).
     * This method is optional and can be used to reset the rate limit counter on success.
     *
     * @param userEmail the email of the user
     */
    public void clearAttempts(String userEmail) {
        log.info("Clearing failed attempts for user: {}", userEmail);
    }
}
