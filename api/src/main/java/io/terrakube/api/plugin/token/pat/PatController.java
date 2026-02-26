package io.terrakube.api.plugin.token.pat;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import io.terrakube.api.rs.token.pat.Pat;
import io.terrakube.api.repository.UserMfaSettingsRepository;

import java.security.Principal;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/pat/v1")
public class PatController {

    private final PatService patService;
    private final UserMfaSettingsRepository userMfaSettingsRepository;

    public PatController(PatService patService, UserMfaSettingsRepository userMfaSettingsRepository) {
        this.patService = patService;
        this.userMfaSettingsRepository = userMfaSettingsRepository;
    }

    @PostMapping
    public ResponseEntity<?> createToken(@RequestBody PatTokenRequest patTokenRequest, Principal principal) {
        JwtAuthenticationToken principalJwt = ((JwtAuthenticationToken) principal);
        String userEmail = (String) principalJwt.getTokenAttributes().get("email");
        
        // Check if MFA is enabled for this user
        Optional<io.terrakube.api.rs.mfa.UserMfaSettings> mfaSettings = userMfaSettingsRepository.findByUserEmail(userEmail);
        if (mfaSettings.isPresent() && mfaSettings.get().isMfaEnabled()) {
            log.warn("PAT creation blocked for user {} - MFA is enabled", userEmail);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "PAT creation disabled when MFA is enabled");
            errorResponse.put("mfaEnabled", true);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
        }
        
        // Existing PAT creation logic
        PatResponse patResponse = new PatResponse();
        log.info("{}", principalJwt);
        patResponse.setToken(patService.createToken(
                patTokenRequest.getDays(),
                patTokenRequest.getDescription(),
                principalJwt.getTokenAttributes().get("name"),
                userEmail,
                principalJwt.getTokenAttributes().get("groups")
            )
        );
        return new ResponseEntity<>(patResponse, HttpStatus.CREATED);
    }

    @GetMapping
    public ResponseEntity<List<Pat>> searchToken(Principal principal){
        return new ResponseEntity<>(patService.searchToken(principal), HttpStatus.ACCEPTED);
    }

    @Transactional
    @DeleteMapping(path = "/{tokenId}")
    public ResponseEntity<String> deleteToken(@PathVariable("tokenId") String tokenId){
        if(patService.deleteToken(tokenId)) {
            return ResponseEntity.accepted().build();
        } else {
            return ResponseEntity.badRequest().build();
        }
    }

    @Getter
    @Setter
    private class PatResponse {
        private String token;
    }

    @Getter
    @Setter
    public static class PatTokenRequest {

        private int days;
        private String description;
    }
}
