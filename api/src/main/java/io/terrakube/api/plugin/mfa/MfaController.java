package io.terrakube.api.plugin.mfa;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import io.terrakube.api.plugin.security.user.AuthenticatedUser;
import com.yahoo.elide.core.security.User;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.terrakube.api.plugin.mfa.backup.BackupCodeService;
import io.terrakube.api.plugin.mfa.session.MfaSessionService;
import io.terrakube.api.plugin.mfa.totp.TotpService;
import io.terrakube.api.plugin.mfa.ratelimit.MfaRateLimitService;
import io.terrakube.api.plugin.mfa.webauthn.WebAuthnService;
import io.terrakube.api.repository.MfaCredentialRepository;
import io.terrakube.api.repository.UserMfaSettingsRepository;
import io.terrakube.api.rs.mfa.MfaCredential;
import io.terrakube.api.rs.mfa.UserMfaSettings;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/mfa/v1")
public class MfaController {

    private static final ObjectConverter OBJECT_CONVERTER = new ObjectConverter();
    private static final String TOTP_TYPE = "TOTP";

    private final UserMfaSettingsRepository userMfaSettingsRepository;
    private final MfaCredentialRepository mfaCredentialRepository;
    private final BackupCodeService backupCodeService;
    private final WebAuthnService webAuthnService;
    private final TotpService totpService;
    private final MfaSessionService mfaSessionService;
    private final MfaRateLimitService mfaRateLimitService;
    private final AuthenticatedUser authenticatedUser;

    public MfaController(UserMfaSettingsRepository userMfaSettingsRepository,
                         MfaCredentialRepository mfaCredentialRepository,
                         BackupCodeService backupCodeService,
                         WebAuthnService webAuthnService,
                         TotpService totpService,
                         MfaSessionService mfaSessionService,
                         MfaRateLimitService mfaRateLimitService,
                         AuthenticatedUser authenticatedUser) {
        this.userMfaSettingsRepository = userMfaSettingsRepository;
        this.mfaCredentialRepository = mfaCredentialRepository;
        this.backupCodeService = backupCodeService;
        this.webAuthnService = webAuthnService;
        this.totpService = totpService;
        this.mfaSessionService = mfaSessionService;
        this.mfaRateLimitService = mfaRateLimitService;
        this.authenticatedUser = authenticatedUser;
    }

    private String getCurrentUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Object email = jwtAuth.getTokenAttributes().get("email");
            if (email != null) {
                return email.toString();
            }
        }
        return authentication.getName();
    }

    @GetMapping("/methods")
    public ResponseEntity<Map<String, Object>> getMethods() {
        String userEmail = getCurrentUserEmail();
        List<MfaCredential> credentials = mfaCredentialRepository.findByUserEmail(userEmail);
        List<String> methods = credentials.stream()
                .map(MfaCredential::getType)
                .distinct()
                .collect(Collectors.toList());
        return ResponseEntity.ok(Map.of("methods", methods));
    }

    @GetMapping("/status")
    public ResponseEntity<MfaStatusResponse> getStatus() {
        String userEmail = getCurrentUserEmail();
        log.info("Fetching MFA status for user: {}", userEmail);

        // Get MFA settings
        Optional<UserMfaSettings> mfaSettings = userMfaSettingsRepository.findByUserEmail(userEmail);
        boolean mfaEnabled = mfaSettings.isPresent() && mfaSettings.get().isMfaEnabled();

        // Get enabled MFA methods
        List<MfaCredential> credentials = mfaCredentialRepository.findByUserEmail(userEmail);
        List<MfaMethodInfo> methods = credentials.stream()
                .filter(c -> !c.getType().equals("BACKUP_CODE"))
                .map(c -> {
                    MfaMethodInfo info = new MfaMethodInfo();
                    info.setId(c.getId().toString());
                    info.setType(c.getType());
                    info.setName(c.getName());
                    info.setCreatedAt(c.getCreatedDate() != null ? c.getCreatedDate().toString() : null);
                    return info;
                })
                .collect(Collectors.toList());

        // Get remaining backup codes
        int backupCodesRemaining = backupCodeService.getBackupCodesCount(userEmail);

        MfaStatusResponse response = new MfaStatusResponse();
        response.setMfaEnabled(mfaEnabled);
        response.setMfaVerified(mfaEnabled && mfaSessionService.isMfaVerified(userEmail));
        response.setMethods(methods);
        response.setBackupCodesRemaining(backupCodesRemaining);

        log.info("MFA status retrieved for user: {} - Enabled: {}, Methods: {}, Backup codes: {}",
                userEmail, mfaEnabled, methods, backupCodesRemaining);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/webauthn/authenticate/options")
    public ResponseEntity<String> getWebAuthnAuthOptions() {
        String userEmail = getCurrentUserEmail();
        log.info("Generating WebAuthn authentication options for user: {}", userEmail);

        PublicKeyCredentialRequestOptions options = webAuthnService.generateAuthenticationOptions(userEmail);
        String optionsJson = OBJECT_CONVERTER.getJsonConverter().writeValueAsString(options);

        log.info("WebAuthn authentication options generated for user: {}", userEmail);
        return new ResponseEntity<>(optionsJson, HttpStatus.OK);
    }

    @PostMapping("/webauthn/authenticate/verify")
    public ResponseEntity<WebAuthnAuthVerifyResponse> verifyWebAuthnAuth(
            @RequestBody WebAuthnAuthVerifyRequest request, HttpServletRequest httpRequest) {
        String userEmail = getCurrentUserEmail();
        log.info("Verifying WebAuthn authentication for user: {}", userEmail);

        if (!mfaRateLimitService.checkRateLimit(userEmail)) {
            log.warn("Rate limit exceeded for MFA verification for user: {}", userEmail);
            return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
        }

        boolean verified = webAuthnService.verifyAuthentication(userEmail, request.getAssertion());
        mfaRateLimitService.recordAttempt(userEmail, "WEBAUTHN", verified, httpRequest.getRemoteAddr());

        WebAuthnAuthVerifyResponse response = new WebAuthnAuthVerifyResponse();
        response.setVerified(verified);

        if (verified) {
            mfaSessionService.markMfaVerified(userEmail);
            log.info("WebAuthn authentication verified successfully for user: {}", userEmail);
        } else {
            log.warn("WebAuthn authentication verification failed for user: {}", userEmail);
        }

        return new ResponseEntity<>(response, verified ? HttpStatus.OK : HttpStatus.UNAUTHORIZED);
    }

    // ==================== WebAuthn Registration Endpoints ====================

    @PostMapping("/webauthn/register/options")
    public ResponseEntity<String> getWebAuthnRegisterOptions(
            @RequestBody(required = false) WebAuthnRegisterOptionsRequest request) {
        String userEmail = getCurrentUserEmail();
        log.info("Generating WebAuthn registration options for user: {}", userEmail);

        if (!mfaRateLimitService.checkRateLimit(userEmail)) {
            return ResponseEntity.status(429).body("{\"error\": \"Too many requests\"}");
        }

        String authenticatorAttachment = request != null ? request.getAuthenticatorAttachment() : null;
        try {
            String options = webAuthnService.generateRegistrationOptions(userEmail, authenticatorAttachment);
            return ResponseEntity.ok(options);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid authenticator attachment type: {}", authenticatorAttachment);
            return ResponseEntity.badRequest().body("{\"error\": \"Invalid authenticator attachment type: " + authenticatorAttachment + "\"}");
        }
    }

    @PostMapping("/webauthn/register/verify")
    public ResponseEntity<Map<String, Object>> verifyWebAuthnRegistration(
            @RequestBody WebAuthnRegisterVerifyRequest request) {
        String userEmail = getCurrentUserEmail();
        log.info("Verifying WebAuthn registration for user: {}", userEmail);

        if (!mfaRateLimitService.checkRateLimit(userEmail)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests"));
        }

        boolean verified = webAuthnService.verifyRegistration(userEmail, request.getCredential(), request.getName());

        if (verified) {
            // Enable MFA for user
            UserMfaSettings mfaSettings = userMfaSettingsRepository.findByUserEmail(userEmail)
                    .orElseGet(() -> {
                        UserMfaSettings newSettings = new UserMfaSettings();
                        newSettings.setUserEmail(userEmail);
                        return newSettings;
                    });
            mfaSettings.setMfaEnabled(true);
            if (mfaSettings.getPreferredMethod() == null) {
                mfaSettings.setPreferredMethod("WEBAUTHN");
            }
            userMfaSettingsRepository.save(mfaSettings);

            log.info("WebAuthn registration successful for user: {}", userEmail);
            return ResponseEntity.ok(Map.of("success", true, "message", "WebAuthn credential registered successfully"));
        }

        log.warn("WebAuthn registration failed for user: {}", userEmail);
        return ResponseEntity.badRequest().body(Map.of("success", false, "message", "WebAuthn registration failed"));
    }

    @GetMapping("/webauthn/credentials")
    public ResponseEntity<List<WebAuthnCredentialResponse>> listWebAuthnCredentials() {
        String userEmail = getCurrentUserEmail();
        log.info("Listing WebAuthn credentials for user: {}", userEmail);

        List<MfaCredential> credentials = mfaCredentialRepository.findByUserEmailAndType(userEmail, "WEBAUTHN");
        List<WebAuthnCredentialResponse> response = credentials.stream()
                .map(cred -> {
                    WebAuthnCredentialResponse dto = new WebAuthnCredentialResponse();
                    dto.setId(cred.getId().toString());
                    dto.setName(cred.getName());
                    dto.setCreatedDate(cred.getCreatedDate());
                    dto.setLastUsedDate(cred.getLastUsedDate());
                    return dto;
                })
                .collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }

    @PatchMapping("/webauthn/credentials/{id}")
    public ResponseEntity<Map<String, Object>> renameWebAuthnCredential(@PathVariable UUID id, @RequestBody Map<String, String> body) {
        String userEmail = getCurrentUserEmail();
        String newName = body.get("name");
        if (newName == null || newName.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Name is required"));
        }

        Optional<MfaCredential> credentialOpt = mfaCredentialRepository.findByIdAndUserEmail(id, userEmail);
        if (credentialOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("success", false, "message", "Credential not found"));
        }

        MfaCredential credential = credentialOpt.get();
        credential.setName(newName.trim());
        mfaCredentialRepository.save(credential);

        log.info("WebAuthn credential {} renamed to '{}' for user: {}", id, newName.trim(), userEmail);
        return ResponseEntity.ok(Map.of("success", true, "message", "Credential renamed successfully"));
    }

    @DeleteMapping("/webauthn/credentials/{id}")
    public ResponseEntity<Map<String, Object>> deleteWebAuthnCredential(@PathVariable UUID id) {
        String userEmail = getCurrentUserEmail();
        log.info("Deleting WebAuthn credential {} for user: {}", id, userEmail);

        // Verify credential belongs to user
        Optional<MfaCredential> credentialOpt = mfaCredentialRepository.findByIdAndUserEmail(id, userEmail);
        if (credentialOpt.isEmpty()) {
            log.warn("WebAuthn credential {} not found for user: {}", id, userEmail);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("success", false, "message", "Credential not found"));
        }

        mfaCredentialRepository.delete(credentialOpt.get());
        log.info("WebAuthn credential {} deleted for user: {}", id, userEmail);

        // Check if user has any other MFA methods
        List<MfaCredential> remainingCredentials = mfaCredentialRepository.findByUserEmail(userEmail);
        boolean hasOtherMfaMethods = remainingCredentials.stream()
                .anyMatch(cred -> !cred.getType().equals("BACKUP_CODE"));

        if (!hasOtherMfaMethods) {
            // Disable MFA if no other methods exist
            userMfaSettingsRepository.findByUserEmail(userEmail).ifPresent(settings -> {
                settings.setMfaEnabled(false);
                userMfaSettingsRepository.save(settings);
                log.info("MFA disabled for user {} as no other MFA methods exist", userEmail);
            });
        }

        return ResponseEntity.ok(Map.of("success", true, "message", "Credential deleted successfully"));
    }

    @PostMapping("/backup-codes/generate")
    public ResponseEntity<BackupCodesGenerateResponse> generateBackupCodes() {
        String userEmail = getCurrentUserEmail();
        log.info("Generating backup codes for user: {}", userEmail);

        List<String> codes = backupCodeService.generateBackupCodes(userEmail);
        BackupCodesGenerateResponse response = new BackupCodesGenerateResponse();
        response.setCodes(codes);

        log.info("Backup codes generated for user: {}", userEmail);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/backup-codes/verify")
    public ResponseEntity<BackupCodeVerifyResponse> verifyBackupCode(
            @RequestBody BackupCodeVerifyRequest request, HttpServletRequest httpRequest) {
        String userEmail = getCurrentUserEmail();
        log.info("Verifying backup code for user: {}", userEmail);

        if (!mfaRateLimitService.checkRateLimit(userEmail)) {
            log.warn("Rate limit exceeded for MFA verification for user: {}", userEmail);
            return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
        }

        boolean verified = backupCodeService.verifyBackupCode(userEmail, request.getCode());
        mfaRateLimitService.recordAttempt(userEmail, "BACKUP_CODE", verified, httpRequest.getRemoteAddr());

        BackupCodeVerifyResponse response = new BackupCodeVerifyResponse();
        response.setVerified(verified);

        if (verified) {
            mfaSessionService.markMfaVerified(userEmail);
        }

        log.info("Backup code verification result for user: {} - Verified: {}", userEmail, verified);
        return new ResponseEntity<>(response, verified ? HttpStatus.OK : HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/backup-codes/count")
    public ResponseEntity<BackupCodesCountResponse> getBackupCodesCount() {
        String userEmail = getCurrentUserEmail();
        log.info("Fetching backup codes count for user: {}", userEmail);

        int count = backupCodeService.getBackupCodesCount(userEmail);
        BackupCodesCountResponse response = new BackupCodesCountResponse();
        response.setCount(count);

        log.info("Backup codes count for user: {} - Count: {}", userEmail, count);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    // ==================== TOTP Endpoints ====================

    @PostMapping("/totp/setup")
    public ResponseEntity<TotpSetupResponse> setupTotp() {
        String userEmail = getCurrentUserEmail();
        log.info("Setting up TOTP for user: {}", userEmail);

        // Generate and store TOTP secret
        String secret = totpService.setupTotp(userEmail, "TOTP Authenticator");

        // Generate QR code data
        String qrCodeUri = totpService.getQrCodeUri(userEmail, secret);
        String qrCodeBase64 = totpService.getQrCodeBase64Png(userEmail, secret);

        TotpSetupResponse response = new TotpSetupResponse();
        response.setSecret(secret);
        response.setQrCodeUri(qrCodeUri);
        response.setQrCodeBase64(qrCodeBase64);

        log.info("TOTP setup completed for user: {}", userEmail);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/totp/verify")
    public ResponseEntity<TotpVerifyResponse> verifyTotp(
            @RequestBody TotpVerifyRequest request, HttpServletRequest httpRequest) {
        String userEmail = getCurrentUserEmail();
        log.info("Verifying TOTP code for user: {}", userEmail);

        if (!mfaRateLimitService.checkRateLimit(userEmail)) {
            log.warn("Rate limit exceeded for MFA verification for user: {}", userEmail);
            return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
        }

        boolean verified = totpService.verifyCodeForUser(userEmail, request.getCode());
        mfaRateLimitService.recordAttempt(userEmail, "TOTP", verified, httpRequest.getRemoteAddr());

        TotpVerifyResponse response = new TotpVerifyResponse();
        response.setVerified(verified);

        if (verified) {
            mfaSessionService.markMfaVerified(userEmail);
            // Enable MFA for the user
            UserMfaSettings mfaSettings = userMfaSettingsRepository.findByUserEmail(userEmail)
                    .orElseGet(() -> {
                        UserMfaSettings newSettings = new UserMfaSettings();
                        newSettings.setUserEmail(userEmail);
                        return newSettings;
                    });
            mfaSettings.setMfaEnabled(true);
            if (mfaSettings.getPreferredMethod() == null) {
                mfaSettings.setPreferredMethod(TOTP_TYPE);
            }
            userMfaSettingsRepository.save(mfaSettings);

            response.setMfaEnabled(true);
            log.info("TOTP verification successful, MFA enabled for user: {}", userEmail);
        } else {
            response.setMfaEnabled(false);
            log.warn("TOTP verification failed for user: {}", userEmail);
        }

        return new ResponseEntity<>(response, verified ? HttpStatus.OK : HttpStatus.UNAUTHORIZED);
    }

    @DeleteMapping("/totp")
    public ResponseEntity<TotpDeleteResponse> deleteTotp() {
        String userEmail = getCurrentUserEmail();
        log.info("Deleting TOTP for user: {}", userEmail);

        // Delete TOTP credentials
        List<MfaCredential> totpCredentials = mfaCredentialRepository.findByUserEmailAndType(userEmail, TOTP_TYPE);
        mfaCredentialRepository.deleteAll(totpCredentials);

        // Check if there are other MFA methods remaining
        List<MfaCredential> remainingCredentials = mfaCredentialRepository.findByUserEmail(userEmail);
        boolean hasOtherMfaMethods = remainingCredentials.stream()
                .anyMatch(cred -> !cred.getType().equals("BACKUP_CODE"));

        // If no other MFA methods, disable MFA
        if (!hasOtherMfaMethods) {
            userMfaSettingsRepository.findByUserEmail(userEmail).ifPresent(settings -> {
                settings.setMfaEnabled(false);
                settings.setPreferredMethod(null);
                userMfaSettingsRepository.save(settings);
            });
        } else {
            // Update preferred method if TOTP was preferred
            userMfaSettingsRepository.findByUserEmail(userEmail).ifPresent(settings -> {
                if (TOTP_TYPE.equals(settings.getPreferredMethod())) {
                    String newPreferred = remainingCredentials.stream()
                            .filter(cred -> !cred.getType().equals("BACKUP_CODE"))
                            .findFirst()
                            .map(MfaCredential::getType)
                            .orElse(null);
                    settings.setPreferredMethod(newPreferred);
                    userMfaSettingsRepository.save(settings);
                }
            });
        }

        TotpDeleteResponse response = new TotpDeleteResponse();
        response.setDeleted(true);
        response.setMfaEnabled(hasOtherMfaMethods);
        response.setMessage("TOTP removed successfully");

        log.info("TOTP deleted for user: {}, MFA still enabled: {}", userEmail, hasOtherMfaMethods);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @DeleteMapping("/admin/reset/{email}")
    public ResponseEntity<AdminResetResponse> adminResetMfa(@PathVariable("email") String targetEmail) {
        String currentUserEmail = getCurrentUserEmail();
        log.info("Admin MFA reset requested by {} for user {}", currentUserEmail, targetEmail);

        // Check if current user is super user
        // TODO: Integrate with IsSuperUser check or GroupService for proper permission validation
        boolean isSuperUser = checkSuperUserPermission(currentUserEmail);
        if (!isSuperUser) {
            log.warn("Unauthorized MFA reset attempt by non-admin user: {}", currentUserEmail);
            return new ResponseEntity<>(new AdminResetResponse(false, "Only super users can reset MFA"), HttpStatus.FORBIDDEN);
        }

        try {
            // Delete all MFA credentials for target user
            List<MfaCredential> credentials = mfaCredentialRepository.findByUserEmail(targetEmail);
            mfaCredentialRepository.deleteAll(credentials);
            log.info("Deleted {} MFA credentials for user {}", credentials.size(), targetEmail);

            // Find and disable MFA for target user
            Optional<UserMfaSettings> mfaSettings = userMfaSettingsRepository.findByUserEmail(targetEmail);
            if (mfaSettings.isPresent()) {
                UserMfaSettings settings = mfaSettings.get();
                settings.setMfaEnabled(false);
                userMfaSettingsRepository.save(settings);
                log.info("Disabled MFA for user {}", targetEmail);
            } else {
                log.info("No MFA settings found for user {}, creating disabled entry", targetEmail);
                UserMfaSettings newSettings = new UserMfaSettings();
                newSettings.setUserEmail(targetEmail);
                newSettings.setMfaEnabled(false);
                userMfaSettingsRepository.save(newSettings);
            }

            // Clear MFA session from Redis
            mfaSessionService.clearMfaSession(targetEmail);

            log.info("Successfully reset MFA for user {} by admin {}", targetEmail, currentUserEmail);
            return new ResponseEntity<>(new AdminResetResponse(true, "MFA reset successfully for user: " + targetEmail), HttpStatus.OK);
        } catch (Exception e) {
            log.error("Error resetting MFA for user {}: {}", targetEmail, e.getMessage(), e);
            return new ResponseEntity<>(new AdminResetResponse(false, "Error resetting MFA: " + e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private boolean checkSuperUserPermission(String userEmail) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User elideUser = new User(authentication);
            return authenticatedUser.isSuperUser(elideUser);
        } catch (Exception e) {
            log.warn("Failed to check super user permission for {}: {}", userEmail, e.getMessage());
            return false;
        }
    }

    @Getter
    @Setter
    public static class MfaStatusResponse {
        private boolean mfaEnabled;
        private boolean mfaVerified;
        private List<MfaMethodInfo> methods;
        private int backupCodesRemaining;
    }

    @Getter
    @Setter
    public static class MfaMethodInfo {
        private String id;
        private String type;
        private String name;
        private String createdAt;
    }

    @Getter
    @Setter
    public static class WebAuthnAuthVerifyRequest {
        private Object assertion;
    }

    @Getter
    @Setter
    public static class WebAuthnAuthVerifyResponse {
        private boolean verified;
    }

    @Getter
    @Setter
    public static class WebAuthnRegisterOptionsRequest {
        private String authenticatorAttachment; // "platform" or "cross-platform"
    }

    @Getter
    @Setter
    public static class WebAuthnRegisterVerifyRequest {
        private String credential;
        private String name;
    }

    @Getter
    @Setter
    public static class WebAuthnCredentialResponse {
        private String id;
        private String name;
        private Date createdDate;
        private LocalDateTime lastUsedDate;
    }

    @Getter
    @Setter
    public static class BackupCodesGenerateResponse {
        private List<String> codes;
    }

    @Getter
    @Setter
    public static class BackupCodeVerifyRequest {
        private String code;
    }

    @Getter
    @Setter
    public static class BackupCodeVerifyResponse {
        private boolean verified;
    }

    @Getter
    @Setter
    public static class BackupCodesCountResponse {
        private int count;
    }

    @Getter
    @Setter
    public static class TotpSetupResponse {
        private String secret;
        private String qrCodeUri;
        private String qrCodeBase64;
    }

    @Getter
    @Setter
    public static class TotpVerifyRequest {
        private String code;
    }

    @Getter
    @Setter
    public static class TotpVerifyResponse {
        private boolean verified;
        private boolean mfaEnabled;
    }

    @Getter
    @Setter
    public static class TotpDeleteRequest {
        private String code;
    }

    @Getter
    @Setter
    public static class TotpDeleteResponse {
        private boolean deleted;
        private boolean mfaEnabled;
        private String message;
    }

    @Getter
    @Setter
    public static class AdminResetResponse {
        private boolean success;
        private String message;

        public AdminResetResponse(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }
}
