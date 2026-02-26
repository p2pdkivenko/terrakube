package io.terrakube.api.plugin.mfa.backup;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import io.terrakube.api.repository.MfaCredentialRepository;
import io.terrakube.api.rs.mfa.MfaCredential;

import java.security.SecureRandom;
import java.util.*;

@Slf4j
@Service
public class BackupCodeService {

    private static final String BACKUP_CODE_TYPE = "BACKUP_CODE";
    private static final int BACKUP_CODE_COUNT = 10;
    private static final int BACKUP_CODE_LENGTH = 8;
    private static final String BACKUP_CODE_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final BCryptPasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final MfaCredentialRepository mfaCredentialRepository;

    public BackupCodeService(MfaCredentialRepository mfaCredentialRepository) {
        this.mfaCredentialRepository = mfaCredentialRepository;
    }

    /**
     * Generate 10 random backup codes for a user.
     * Deletes any existing backup codes before generating new ones.
     *
     * @param userEmail User's email address
     * @return List of 10 plaintext backup codes (for one-time display only)
     */
    public List<String> generateBackupCodes(String userEmail) {
        log.info("Generating backup codes for user: {}", userEmail);

        // Delete existing backup codes
        List<MfaCredential> existingCodes = mfaCredentialRepository.findByUserEmailAndType(userEmail, BACKUP_CODE_TYPE);
        if (!existingCodes.isEmpty()) {
            log.info("Deleting {} existing backup codes for user: {}", existingCodes.size(), userEmail);
            mfaCredentialRepository.deleteAll(existingCodes);
        }

        List<String> plainCodes = new ArrayList<>();
        List<MfaCredential> credentialsToSave = new ArrayList<>();

        // Generate 10 codes
        for (int i = 1; i <= BACKUP_CODE_COUNT; i++) {
            String plainCode = generateRandomCode();
            plainCodes.add(plainCode);

            // Hash the code
            String hashedCode = PASSWORD_ENCODER.encode(plainCode);

            // Create credential entry
            MfaCredential credential = new MfaCredential();
            credential.setUserEmail(userEmail);
            credential.setType(BACKUP_CODE_TYPE);
            credential.setName("Backup Code " + i);

            // Store hashed code and used flag in JSON
            try {
                Map<String, Object> credentialData = new HashMap<>();
                credentialData.put("hashedCode", hashedCode);
                credentialData.put("used", false);
                credential.setCredentialData(OBJECT_MAPPER.writeValueAsString(credentialData));
            } catch (Exception e) {
                log.error("Error serializing credential data for user: {}", userEmail, e);
                throw new RuntimeException("Failed to serialize backup code credential data", e);
            }

            credentialsToSave.add(credential);
        }

        // Save all credentials
        mfaCredentialRepository.saveAll(credentialsToSave);
        log.info("Successfully generated {} backup codes for user: {}", BACKUP_CODE_COUNT, userEmail);

        return plainCodes;
    }

    /**
     * Verify a backup code for a user.
     * Marks the code as used if verification succeeds.
     *
     * @param userEmail User's email address
     * @param code      The backup code to verify
     * @return true if code is valid and unused, false otherwise
     */
    public boolean verifyBackupCode(String userEmail, String code) {
        log.info("Verifying backup code for user: {}", userEmail);

        List<MfaCredential> backupCodes = mfaCredentialRepository.findByUserEmailAndType(userEmail, BACKUP_CODE_TYPE);

        for (MfaCredential credential : backupCodes) {
            try {
                Map<String, Object> credentialData = OBJECT_MAPPER.readValue(credential.getCredentialData(), Map.class);
                String hashedCode = (String) credentialData.get("hashedCode");
                Boolean used = (Boolean) credentialData.get("used");

                // Check if code is already used
                if (used != null && used) {
                    log.debug("Backup code already used for user: {}", userEmail);
                    continue;
                }

                // Verify code matches hash
                if (PASSWORD_ENCODER.matches(code, hashedCode)) {
                    log.info("Backup code verified for user: {}", userEmail);

                    // Mark as used
                    credentialData.put("used", true);
                    credential.setCredentialData(OBJECT_MAPPER.writeValueAsString(credentialData));
                    mfaCredentialRepository.save(credential);

                    log.info("Backup code marked as used for user: {}", userEmail);
                    return true;
                }
            } catch (Exception e) {
                log.error("Error verifying backup code for user: {}", userEmail, e);
            }
        }

        log.warn("Backup code verification failed for user: {}", userEmail);
        return false;
    }

    /**
     * Get the count of remaining unused backup codes for a user.
     *
     * @param userEmail User's email address
     * @return Number of unused backup codes
     */
    public int getBackupCodesCount(String userEmail) {
        List<MfaCredential> backupCodes = mfaCredentialRepository.findByUserEmailAndType(userEmail, BACKUP_CODE_TYPE);

        int unusedCount = 0;
        for (MfaCredential credential : backupCodes) {
            try {
                Map<String, Object> credentialData = OBJECT_MAPPER.readValue(credential.getCredentialData(), Map.class);
                Boolean used = (Boolean) credentialData.get("used");

                if (used == null || !used) {
                    unusedCount++;
                }
            } catch (Exception e) {
                log.error("Error reading backup code data for user: {}", userEmail, e);
            }
        }

        log.debug("User {} has {} unused backup codes", userEmail, unusedCount);
        return unusedCount;
    }

    /**
     * Generate a random 8-character alphanumeric code.
     * Uses uppercase letters and digits only.
     *
     * @return Random backup code
     */
    private String generateRandomCode() {
        StringBuilder code = new StringBuilder(BACKUP_CODE_LENGTH);
        for (int i = 0; i < BACKUP_CODE_LENGTH; i++) {
            int randomIndex = SECURE_RANDOM.nextInt(BACKUP_CODE_CHARSET.length());
            code.append(BACKUP_CODE_CHARSET.charAt(randomIndex));
        }
        return code.toString();
    }
}
