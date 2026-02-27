package io.terrakube.api.plugin.mfa.totp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import io.terrakube.api.plugin.security.encryption.EncryptionService;
import io.terrakube.api.repository.MfaCredentialRepository;
import io.terrakube.api.rs.mfa.MfaCredential;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class TotpService {

    private static final String TOTP_TYPE = "TOTP";
    private static final String DEFAULT_CREDENTIAL_NAME = "TOTP Authenticator";
    private static final String ISSUER = "Terrakube";
    private static final int SECRET_LENGTH = 32;
    private static final int CODE_DIGITS = 6;
    private static final int TIME_PERIOD_SECONDS = 30;
    private static final int ALLOWED_TIME_PERIOD_DISCREPANCY = 1;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final MfaCredentialRepository mfaCredentialRepository;
    private final EncryptionService encryptionService;
    private final SecretGenerator secretGenerator;
    private final CodeVerifier codeVerifier;

    public TotpService(MfaCredentialRepository mfaCredentialRepository, EncryptionService encryptionService) {
        this.mfaCredentialRepository = mfaCredentialRepository;
        this.encryptionService = encryptionService;
        this.secretGenerator = new DefaultSecretGenerator(SECRET_LENGTH);

        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, CODE_DIGITS);
        DefaultCodeVerifier defaultCodeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        defaultCodeVerifier.setTimePeriod(TIME_PERIOD_SECONDS);
        defaultCodeVerifier.setAllowedTimePeriodDiscrepancy(ALLOWED_TIME_PERIOD_DISCREPANCY);
        this.codeVerifier = defaultCodeVerifier;
    }

    public String generateSecret() {
        return secretGenerator.generate();
    }

    public String getQrCodeUri(String email, String secret) {
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
                ISSUER,
                email,
                secret,
                ISSUER,
                CODE_DIGITS,
                TIME_PERIOD_SECONDS
        );
    }

    public String getQrCodeBase64Png(String email, String secret) {
        try {
            String otpAuthUri = getQrCodeUri(email, secret);
            BitMatrix bitMatrix = new QRCodeWriter().encode(otpAuthUri, BarcodeFormat.QR_CODE, 256, 256);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
            return Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (WriterException | IOException e) {
            log.error("Unable to generate TOTP QR code for user: {}", email, e);
            throw new RuntimeException("Unable to generate TOTP QR code", e);
        }
    }

    public boolean verifyCode(String secret, String code) {
        return codeVerifier.isValidCode(secret, code);
    }

    public String setupTotp(String userEmail, String credentialName) {
        String secret = generateSecret();
        String encryptedSecret = encryptionService.encrypt(secret);

        MfaCredential credential = new MfaCredential();
        credential.setUserEmail(userEmail);
        credential.setType(TOTP_TYPE);
        credential.setName((credentialName == null || credentialName.isBlank()) ? DEFAULT_CREDENTIAL_NAME : credentialName);

        try {
            Map<String, Object> credentialData = new HashMap<>();
            credentialData.put("encryptedSecret", encryptedSecret);
            credentialData.put("algorithm", "SHA1");
            credentialData.put("digits", CODE_DIGITS);
            credentialData.put("period", TIME_PERIOD_SECONDS);
            credential.setCredentialData(OBJECT_MAPPER.writeValueAsString(credentialData));
        } catch (Exception e) {
            log.error("Unable to serialize TOTP credential for user: {}", userEmail, e);
            throw new RuntimeException("Unable to serialize TOTP credential", e);
        }

        List<MfaCredential> existingTotpCredentials = mfaCredentialRepository.findByUserEmailAndType(userEmail, TOTP_TYPE);
        if (!existingTotpCredentials.isEmpty()) {
            mfaCredentialRepository.deleteAll(existingTotpCredentials);
        }

        mfaCredentialRepository.save(credential);
        return secret;
    }

    public boolean verifyCodeForUser(String userEmail, String code) {
        List<MfaCredential> totpCredentials = mfaCredentialRepository.findByUserEmailAndType(userEmail, TOTP_TYPE);
        if (totpCredentials.isEmpty()) {
            return false;
        }

        MfaCredential credential = totpCredentials.get(0);
        try {
            Map<String, Object> credentialData = OBJECT_MAPPER.readValue(credential.getCredentialData(), Map.class);
            String encryptedSecret = (String) credentialData.get("encryptedSecret");
            String secret = encryptionService.decrypt(encryptedSecret);
            return verifyCode(secret, code);
        } catch (Exception e) {
            log.error("Unable to verify TOTP code for user: {}", userEmail, e);
            return false;
        }
    }
}
