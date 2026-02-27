package io.terrakube.api.plugin.mfa.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import io.terrakube.api.repository.MfaCredentialRepository;
import io.terrakube.api.rs.mfa.MfaCredential;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class WebAuthnService {

    private static final String WEBAUTHN_TYPE = "WEBAUTHN";
    private static final String DEFAULT_CREDENTIAL_NAME = "Security Key";
    private static final int CHALLENGE_SIZE = 32;
    private static final long DEFAULT_TIMEOUT_MS = 60_000L;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final ObjectConverter OBJECT_CONVERTER = new ObjectConverter();
    private static final WebAuthnManager WEB_AUTHN_MANAGER = WebAuthnManager.createNonStrictWebAuthnManager();

    private final MfaCredentialRepository mfaCredentialRepository;
    private final Map<String, Challenge> registrationChallenges = new ConcurrentHashMap<>();
    private final Map<String, Challenge> authenticationChallenges = new ConcurrentHashMap<>();

    @Value("${io.terrakube.hostname:http://localhost:8080}")
    private String hostname;


    @Value("${io.terrakube.mfa.webauthn.rp-name:Terrakube}")
    private String rpName;

    public WebAuthnService(MfaCredentialRepository mfaCredentialRepository) {
        this.mfaCredentialRepository = mfaCredentialRepository;
    }

    public String generateRegistrationOptions(String userEmail) {
        return generateRegistrationOptions(userEmail, null);
    }

    public String generateRegistrationOptions(String userEmail, String authenticatorAttachment) {
        Challenge challenge = createChallenge();
        registrationChallenges.put(userEmail, challenge);

        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(resolveRpId(), rpName);
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(
                userEmail.getBytes(StandardCharsets.UTF_8),
                userEmail,
                userEmail
        );

        List<PublicKeyCredentialDescriptor> excludeCredentials = getRegisteredCredentials(userEmail).stream()
                .map(this::toPublicKeyDescriptor)
                .filter(Objects::nonNull)
                .toList();

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                rp,
                user,
                challenge,
                getPubKeyCredParams(),
                DEFAULT_TIMEOUT_MS,
                excludeCredentials,
                buildAuthenticatorSelection(authenticatorAttachment),
                AttestationConveyancePreference.NONE,
                null
        );

        return OBJECT_CONVERTER.getJsonConverter().writeValueAsString(options);
    }

    public boolean verifyRegistration(String userEmail, String attestationResponse) {
        Challenge challenge = registrationChallenges.remove(userEmail);
        if (challenge == null) {
            log.warn("Missing WebAuthn registration challenge for user: {}", userEmail);
            return false;
        }

        try {
            JsonNode payload = OBJECT_MAPPER.readTree(attestationResponse);
            String credentialName = extractCredentialName(payload);
            String credentialPayload = extractCredentialPayload(payload, attestationResponse);

            RegistrationData registrationData = WEB_AUTHN_MANAGER.parseRegistrationResponseJSON(credentialPayload);
            if (registrationData.getAttestationObject() == null || registrationData.getCollectedClientData() == null) {
                log.warn("Invalid WebAuthn registration payload for user: {}", userEmail);
                return false;
            }

            RegistrationParameters registrationParameters = new RegistrationParameters(
                    createServerProperty(challenge, registrationData.getCollectedClientData().getOrigin()),
                    getPubKeyCredParams(),
                    false,
                    true
            );

            RegistrationData verifiedData = WEB_AUTHN_MANAGER.verify(registrationData, registrationParameters);
            AttestationObject attestationObject = verifiedData.getAttestationObject();
            if (attestationObject == null || attestationObject.getAuthenticatorData() == null) {
                log.warn("Missing attestation object in verified registration data for user: {}", userEmail);
                return false;
            }

            CredentialRecord credentialRecord = new CredentialRecordImpl(
                    attestationObject,
                    verifiedData.getCollectedClientData(),
                    verifiedData.getClientExtensions(),
                    verifiedData.getTransports()
            );

            AttestedCredentialData attestedCredentialData = credentialRecord.getAttestedCredentialData();
            if (attestedCredentialData == null) {
                log.warn("Missing attested credential data for user: {}", userEmail);
                return false;
            }

            Map<String, Object> credentialData = new HashMap<>();
            credentialData.put("credentialId", base64UrlEncode(attestedCredentialData.getCredentialId()));
            credentialData.put(
                    "publicKey",
                    base64UrlEncode(OBJECT_CONVERTER.getCborConverter().writeValueAsBytes(attestedCredentialData.getCOSEKey()))
            );
            credentialData.put("signCount", credentialRecord.getCounter());
            credentialData.put("aaguid", String.valueOf(attestedCredentialData.getAaguid()));
            credentialData.put("transports", toTransportValues(credentialRecord.getTransports()));

            MfaCredential credential = new MfaCredential();
            credential.setUserEmail(userEmail);
            credential.setType(WEBAUTHN_TYPE);
            credential.setName(credentialName);
            credential.setCredentialData(OBJECT_MAPPER.writeValueAsString(credentialData));
            mfaCredentialRepository.save(credential);
            return true;
        } catch (Exception e) {
            log.error("Error verifying WebAuthn registration for user: {}", userEmail, e);
            return false;
        }
    }

    public PublicKeyCredentialRequestOptions generateAuthenticationOptions(String userEmail) {
        Challenge challenge = createChallenge();
        authenticationChallenges.put(userEmail, challenge);

        List<PublicKeyCredentialDescriptor> allowCredentials = getRegisteredCredentials(userEmail).stream()
                .map(this::toPublicKeyDescriptor)
                .filter(Objects::nonNull)
                .toList();

        return new PublicKeyCredentialRequestOptions(
                challenge,
                DEFAULT_TIMEOUT_MS,
                resolveRpId(),
                allowCredentials,
                UserVerificationRequirement.PREFERRED,
                null
        );
    }

    public boolean verifyAuthentication(String userEmail, Object assertionResponse) {
        Challenge challenge = authenticationChallenges.remove(userEmail);
        if (challenge == null) {
            log.warn("Missing WebAuthn authentication challenge for user: {}", userEmail);
            return false;
        }

        try {
            AuthenticationData authenticationData = WEB_AUTHN_MANAGER.parseAuthenticationResponseJSON(toJson(assertionResponse));
            List<MfaCredential> credentials = getRegisteredCredentials(userEmail);

            MfaCredential matchingCredential = findMatchingCredential(credentials, authenticationData.getCredentialId());
            if (matchingCredential == null) {
                log.warn("No matching WebAuthn credential found for user: {}", userEmail);
                return false;
            }

            CredentialRecord credentialRecord = toCredentialRecord(matchingCredential);
            List<byte[]> allowCredentials = credentials.stream()
                    .map(this::extractCredentialId)
                    .filter(Objects::nonNull)
                    .toList();

            AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                    createServerProperty(challenge),
                    credentialRecord,
                    allowCredentials,
                    true,
                    true
            );

            WEB_AUTHN_MANAGER.verify(authenticationData, authenticationParameters);

            updateCredentialAfterAuthentication(
                    matchingCredential,
                    authenticationData.getAuthenticatorData().getSignCount()
            );

            return true;
        } catch (Exception e) {
            log.error("Error verifying WebAuthn authentication for user: {}", userEmail, e);
            return false;
        }
    }

    private List<MfaCredential> getRegisteredCredentials(String userEmail) {
        return mfaCredentialRepository.findByUserEmailAndType(userEmail, WEBAUTHN_TYPE);
    }

    private List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
        );
    }

    private Challenge createChallenge() {
        byte[] challengeBytes = new byte[CHALLENGE_SIZE];
        SECURE_RANDOM.nextBytes(challengeBytes);
        return new DefaultChallenge(challengeBytes);
    }

    private ServerProperty createServerProperty(Challenge challenge) {
        return createServerProperty(challenge, null);
    }

    private ServerProperty createServerProperty(Challenge challenge, Origin requestOrigin) {
        return new ServerProperty(
                new Origin(resolveOrigin(requestOrigin)),
                resolveRpId(requestOrigin),
                challenge
        );
    }

    private String resolveOrigin(Origin requestOrigin) {
        // Use TerrakubeHostname as primary, fallback to request origin
        if (hostname != null && !hostname.isBlank()) {
            return hostname;
        }
        if (requestOrigin != null) {
            return requestOrigin.toString();
        }
        return "http://localhost:8080";
    }

    private String resolveRpId() {
        return resolveRpId(null);
    }

    private String resolveRpId(Origin requestOrigin) {
        try {
            URI uri = URI.create(resolveOrigin(requestOrigin));
            if (uri.getHost() != null && !uri.getHost().isBlank()) {
                return uri.getHost();
            }
        } catch (IllegalArgumentException e) {
            log.warn("Invalid WebAuthn origin configured: {}", resolveOrigin(requestOrigin));
        }
        return "localhost";
    }

    private String toJson(Object response) {
        if (response instanceof String responseJson) {
            return responseJson;
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(response);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to serialize WebAuthn response payload", e);
        }
    }

    private PublicKeyCredentialDescriptor toPublicKeyDescriptor(MfaCredential credential) {
        byte[] credentialId = extractCredentialId(credential);
        if (credentialId == null) {
            return null;
        }

        Set<AuthenticatorTransport> transports = null;
        try {
            Map<String, Object> data = readCredentialData(credential);
            Object transportsRaw = data.get("transports");
            if (transportsRaw instanceof Collection<?> transportCollection) {
                transports = new HashSet<>();
                for (Object transport : transportCollection) {
                    if (transport instanceof String transportValue && !transportValue.isBlank()) {
                        transports.add(AuthenticatorTransport.create(transportValue));
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Unable to parse transports for WebAuthn credential: {}", credential.getId());
        }

        return new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialId, transports);
    }

    private byte[] extractCredentialId(MfaCredential credential) {
        try {
            Map<String, Object> data = readCredentialData(credential);
            Object credentialId = data.get("credentialId");
            if (!(credentialId instanceof String credentialIdValue) || credentialIdValue.isBlank()) {
                return null;
            }
            return base64UrlDecode(credentialIdValue);
        } catch (Exception e) {
            log.warn("Unable to parse credentialId for WebAuthn credential: {}", credential.getId());
            return null;
        }
    }

    private CredentialRecord toCredentialRecord(MfaCredential credential) throws Exception {
        Map<String, Object> data = readCredentialData(credential);

        byte[] credentialId = base64UrlDecode((String) data.get("credentialId"));
        byte[] publicKey = base64UrlDecode((String) data.get("publicKey"));
        long signCount = toLong(data.get("signCount"));
        String aaguidValue = (String) data.get("aaguid");

        COSEKey coseKey = OBJECT_CONVERTER.getCborConverter().readValue(publicKey, COSEKey.class);
        AttestedCredentialData attestedCredentialData = new AttestedCredentialData(
                (aaguidValue == null || aaguidValue.isBlank() || "null".equalsIgnoreCase(aaguidValue))
                        ? AAGUID.ZERO
                        : new AAGUID(aaguidValue),
                credentialId,
                coseKey
        );

        return new CredentialRecordImpl(
                null,
                null,
                null,
                null,
                signCount,
                attestedCredentialData,
                null,
                null,
                null,
                null
        );
    }

    private MfaCredential findMatchingCredential(List<MfaCredential> credentials, byte[] credentialId) {
        String encodedCredentialId = base64UrlEncode(credentialId);
        for (MfaCredential credential : credentials) {
            try {
                Map<String, Object> data = readCredentialData(credential);
                if (encodedCredentialId.equals(data.get("credentialId"))) {
                    return credential;
                }
            } catch (Exception e) {
                log.warn("Unable to parse credential data for credential: {}", credential.getId());
            }
        }
        return null;
    }

    private void updateCredentialAfterAuthentication(MfaCredential credential, long signCount) throws Exception {
        Map<String, Object> data = readCredentialData(credential);
        data.put("signCount", signCount);
        credential.setCredentialData(OBJECT_MAPPER.writeValueAsString(data));
        credential.setLastUsedDate(LocalDateTime.now());
        mfaCredentialRepository.save(credential);
    }

    private Map<String, Object> readCredentialData(MfaCredential credential) throws Exception {
        return OBJECT_MAPPER.readValue(credential.getCredentialData(), Map.class);
    }

    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private byte[] base64UrlDecode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    private long toLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(String.valueOf(value));
    }

    private List<String> toTransportValues(Set<AuthenticatorTransport> transports) {
        if (transports == null || transports.isEmpty()) {
            return Collections.emptyList();
        }
        return transports.stream()
                .map(AuthenticatorTransport::getValue)
                .toList();
    }

    private AuthenticatorSelectionCriteria buildAuthenticatorSelection(String authenticatorAttachment) {
        if (authenticatorAttachment == null || authenticatorAttachment.isBlank()) {
            return null;
        }

        if (!"platform".equals(authenticatorAttachment) && !"cross-platform".equals(authenticatorAttachment)) {
            throw new IllegalArgumentException("Unsupported authenticator attachment");
        }

        return new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.create(authenticatorAttachment),
                false,
                UserVerificationRequirement.PREFERRED
        );
    }

    private String extractCredentialName(JsonNode payload) {
        JsonNode nameNode = payload.get("name");
        if (nameNode == null || nameNode.asText().isBlank()) {
            return DEFAULT_CREDENTIAL_NAME;
        }
        return nameNode.asText();
    }

    private String extractCredentialPayload(JsonNode payload, String rawPayload) {
        if (payload.has("id") && payload.has("response")) {
            return rawPayload;
        }

        JsonNode credentialNode = payload.get("credential");
        if (credentialNode == null || credentialNode.isNull()) {
            throw new IllegalArgumentException("Missing credential payload");
        }

        try {
            return OBJECT_MAPPER.writeValueAsString(credentialNode);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to serialize credential payload", e);
        }
    }
}
