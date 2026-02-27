package io.terrakube.api.plugin.mfa.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.terrakube.api.plugin.mfa.session.MfaSessionService;
import io.terrakube.api.repository.UserMfaSettingsRepository;
import io.terrakube.api.rs.mfa.UserMfaSettings;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
public class MfaVerificationFilter extends OncePerRequestFilter {

    private static final String JWT_TYPE_PAT = "Terrakube";
    private static final String JWT_TYPE_INTERNAL = "TerrakubeInternal";

    private static final String MFA_REQUIRED_RESPONSE =
            "{\"mfaRequired\":true,\"message\":\"MFA verification required\"}";

    private static final List<String> EXEMPT_PATHS = List.of(
            "/mfa/v1/**",
            "/actuator/**",
            "/error",
            "/callback/v1/**",
            "/webhook/v1/**",
            "/.well-known/**"
    );

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private final UserMfaSettingsRepository userMfaSettingsRepository;
    private final MfaSessionService mfaSessionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public MfaVerificationFilter(UserMfaSettingsRepository userMfaSettingsRepository,
                                  MfaSessionService mfaSessionService) {
        this.userMfaSettingsRepository = userMfaSettingsRepository;
        this.mfaSessionService = mfaSessionService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return EXEMPT_PATHS.stream().anyMatch(pattern -> PATH_MATCHER.match(pattern, path));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        String issuer = getJwtClaim(request, "iss");
        if (JWT_TYPE_PAT.equals(issuer) || JWT_TYPE_INTERNAL.equals(issuer)) {
            filterChain.doFilter(request, response);
            return;
        }

        String emailClaim = getJwtClaim(request, "email");
        String userEmail = emailClaim.isBlank() ? authentication.getName() : emailClaim;
        if (userEmail.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<UserMfaSettings> mfaSettings = userMfaSettingsRepository.findByUserEmail(userEmail);
        boolean mfaEnabled = mfaSettings.map(UserMfaSettings::isMfaEnabled).orElse(false);

        long tokenIssuedAt = getTokenIssuedAtSeconds(request);
        if (!mfaEnabled || mfaSessionService.isMfaVerifiedAfter(userEmail, tokenIssuedAt)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.info("MFA verification required for user {}", userEmail);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(MFA_REQUIRED_RESPONSE);
    }

    public void markMfaVerified(String userEmail) {
        mfaSessionService.markMfaVerified(userEmail);
    }

    public boolean isMfaVerified(String userEmail) {
        return mfaSessionService.isMfaVerified(userEmail);
    }

    private long getTokenIssuedAtSeconds(HttpServletRequest request) {
        String iatStr = getJwtClaim(request, "iat");
        if (iatStr.isBlank()) {
            return 0;
        }
        try {
            return Long.parseLong(iatStr);
        } catch (NumberFormatException e) {
            // iat might be a decimal like "1740000000.0"
            return (long) Double.parseDouble(iatStr);
        }
    }

    private String getJwtClaim(HttpServletRequest request, String claim) {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return "";
        }

        String token = authorizationHeader.replace("Bearer ", "");
        String[] tokenChunks = token.split("\\.");
        if (tokenChunks.length < 2) {
            return "";
        }

        try {
            String payload = new String(Base64.getUrlDecoder().decode(tokenChunks[1]), StandardCharsets.UTF_8);
            Map<String, Object> claims = objectMapper.readValue(payload, HashMap.class);
            Object claimValue = claims.get(claim);
            return claimValue != null ? claimValue.toString() : "";
        } catch (IllegalArgumentException | JsonProcessingException exception) {
            log.debug("Unable to parse JWT claim {}", claim, exception);
            return "";
        }
    }
}
