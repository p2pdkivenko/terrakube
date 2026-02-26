package io.terrakube.api;

import io.terrakube.api.repository.MfaCredentialRepository;
import io.terrakube.api.repository.UserMfaSettingsRepository;
import io.terrakube.api.rs.mfa.MfaCredential;
import io.terrakube.api.rs.mfa.UserMfaSettings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.when;

public class MfaIntegrationTest extends ServerApplicationTests {

    private static final String TEST_USER_EMAIL = "test@terrakube.io";
    private static final String ORG_ID = "d9b58bd3-f3fc-4056-a026-1163297e80a8";
    private static final String WORKSPACE_ID = "5ed411ca-7ab8-4d2f-b591-02d0d5788afc";

    @Autowired
    private UserMfaSettingsRepository userMfaSettingsRepository;

    @Autowired
    private MfaCredentialRepository mfaCredentialRepository;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        resetMfaState();
    }

    @Test
    void getMfaStatus() {
        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .get("/mfa/v1/status")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.OK.value())
                .body("mfaEnabled", equalTo(false))
                .body("methods", hasSize(0))
                .body("backupCodesRemaining", equalTo(0));
    }

    @Test
    void setupTotp() {
        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .post("/mfa/v1/totp/setup")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.OK.value())
                .body("secret", notNullValue())
                .body("qrCodeUri", notNullValue())
                .body("qrCodeBase64", notNullValue());
    }

    @Test
    void verifyTotpWithInvalidCode() {
        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"), "Content-Type", "application/json")
                .body("{\"code\":\"000000\"}")
                .when()
                .post("/mfa/v1/totp/verify")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .body("verified", equalTo(false))
                .body("mfaEnabled", equalTo(false));
    }

    @Test
    void generateBackupCodes() {
        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .post("/mfa/v1/backup-codes/generate")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.OK.value())
                .body("codes", hasSize(10));
    }

    @Test
    void verifyBackupCodeAndCount() {
        List<String> codes = given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .post("/mfa/v1/backup-codes/generate")
                .then()
                .assertThat()
                .statusCode(HttpStatus.OK.value())
                .extract().path("codes");

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"), "Content-Type", "application/json")
                .body("{\"code\":\"" + codes.get(0) + "\"}")
                .when()
                .post("/mfa/v1/backup-codes/verify")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.OK.value())
                .body("verified", equalTo(true));

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .get("/mfa/v1/backup-codes/count")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.OK.value())
                .body("count", equalTo(9));
    }

    @Test
    void backupCodesExhaustion() {
        List<String> codes = given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .post("/mfa/v1/backup-codes/generate")
                .then()
                .assertThat()
                .statusCode(HttpStatus.OK.value())
                .extract().path("codes");

        for (String code : codes) {
            given()
                    .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"), "Content-Type", "application/json")
                    .body("{\"code\":\"" + code + "\"}")
                    .when()
                    .post("/mfa/v1/backup-codes/verify")
                    .then()
                    .assertThat()
                    .statusCode(HttpStatus.OK.value())
                    .body("verified", equalTo(true));
        }

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .get("/mfa/v1/backup-codes/count")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.OK.value())
                .body("count", equalTo(0));
    }

    @Test
    void patCreationBlockedWhenMfaEnabled() {
        UserMfaSettings mfaSettings = new UserMfaSettings();
        mfaSettings.setUserEmail(TEST_USER_EMAIL);
        mfaSettings.setMfaEnabled(true);
        mfaSettings.setPreferredMethod("TOTP");
        userMfaSettingsRepository.save(mfaSettings);

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"), "Content-Type", "application/json")
                .body("{\"days\":7,\"description\":\"blocked-pat\"}")
                .when()
                .post("/pat/v1")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .body("mfaEnabled", equalTo(true));
    }

    @Test
    void challengeThenAccessProtectedEndpoint() {
        UserMfaSettings mfaSettings = new UserMfaSettings();
        mfaSettings.setUserEmail(TEST_USER_EMAIL);
        mfaSettings.setMfaEnabled(true);
        mfaSettings.setPreferredMethod("BACKUP_CODE");
        userMfaSettingsRepository.save(mfaSettings);

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .get("/api/v1/organization/" + ORG_ID + "/workspace/" + WORKSPACE_ID + "/access")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .body("mfaRequired", equalTo(true));

        List<String> codes = given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .post("/mfa/v1/backup-codes/generate")
                .then()
                .assertThat()
                .statusCode(HttpStatus.OK.value())
                .extract().path("codes");

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"), "Content-Type", "application/json")
                .body("{\"code\":\"" + codes.get(0) + "\"}")
                .when()
                .post("/mfa/v1/backup-codes/verify")
                .then()
                .assertThat()
                .statusCode(HttpStatus.OK.value())
                .body("verified", equalTo(true));

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .get("/api/v1/organization/" + ORG_ID + "/workspace/" + WORKSPACE_ID + "/access")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.OK.value());
    }

    @Test
    void sixthAttemptFails() {
        for (int attempt = 1; attempt <= 5; attempt++) {
            given()
                    .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"), "Content-Type", "application/json")
                    .body("{\"code\":\"INVALID" + attempt + "\"}")
                    .when()
                    .post("/mfa/v1/backup-codes/verify")
                    .then()
                    .assertThat()
                    .statusCode(HttpStatus.BAD_REQUEST.value());
        }

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"), "Content-Type", "application/json")
                .body("{\"code\":\"INVALID6\"}")
                .when()
                .post("/mfa/v1/backup-codes/verify")
                .then()
                .assertThat()
                .log().all()
                .statusCode(anyOf(
                        equalTo(HttpStatus.BAD_REQUEST.value()),
                        equalTo(HttpStatus.UNAUTHORIZED.value()),
                        equalTo(HttpStatus.TOO_MANY_REQUESTS.value())
                ));
    }

    @Test
    void adminResetRequiresSuperUser() {
        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .delete("/mfa/v1/admin/reset/someone@example.com")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .body("success", equalTo(false));
    }

    @Test
    void mfaStatusIncludesTotpMethodAfterSetup() {
        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .post("/mfa/v1/totp/setup")
                .then()
                .assertThat()
                .statusCode(HttpStatus.OK.value());

        UserMfaSettings mfaSettings = userMfaSettingsRepository.findByUserEmail(TEST_USER_EMAIL)
                .orElseGet(() -> {
                    UserMfaSettings settings = new UserMfaSettings();
                    settings.setUserEmail(TEST_USER_EMAIL);
                    return settings;
                });
        mfaSettings.setMfaEnabled(true);
        mfaSettings.setPreferredMethod("TOTP");
        userMfaSettingsRepository.save(mfaSettings);

        given()
                .headers("Authorization", "Bearer " + generatePAT("TERRAKUBE_ADMIN"))
                .when()
                .get("/mfa/v1/status")
                .then()
                .assertThat()
                .log().all()
                .statusCode(HttpStatus.OK.value())
                .body("mfaEnabled", equalTo(true))
                .body("methods", hasItem("TOTP"))
                .body("backupCodesRemaining", greaterThanOrEqualTo(0));
    }

    private void resetMfaState() {
        List<MfaCredential> credentials = mfaCredentialRepository.findByUserEmail(TEST_USER_EMAIL);
        if (!credentials.isEmpty()) {
            mfaCredentialRepository.deleteAll(credentials);
        }
        userMfaSettingsRepository.findByUserEmail(TEST_USER_EMAIL)
                .ifPresent(userMfaSettingsRepository::delete);
    }
}
