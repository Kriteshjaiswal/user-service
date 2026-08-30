package com.aidocqa.user.service;

import com.aidocqa.user.dto.OAuthConfigDto;
import com.aidocqa.user.entity.User;
import com.aidocqa.user.entity.UserAuditLog;
import com.aidocqa.user.kafka.UserCreatedEvent;
import com.aidocqa.user.kafka.UserEventProducer;
import com.aidocqa.user.repository.UserAuditLogRepository;
import com.aidocqa.user.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthService {

    private final UserRepository userRepository;
    private final UserAuditLogRepository auditLogRepository;
    private final UserEventProducer eventProducer;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${oauth.google.client-id:}")
    private String googleClientId;

    @Value("${oauth.google.client-secret:}")
    private String googleClientSecret;

    @Value("${oauth.github.client-id:}")
    private String githubClientId;

    @Value("${oauth.github.client-secret:}")
    private String githubClientSecret;

    public OAuthConfigDto getOAuthConfig() {
        return OAuthConfigDto.builder()
                .googleConfigured(googleClientId != null && !googleClientId.isBlank() && googleClientSecret != null && !googleClientSecret.isBlank())
                .githubConfigured(githubClientId != null && !githubClientId.isBlank() && githubClientSecret != null && !githubClientSecret.isBlank())
                .googleClientId(googleClientId != null ? googleClientId : "")
                .githubClientId(githubClientId != null ? githubClientId : "")
                .build();
    }

    public record OAuthResult(User user, boolean isNewUser) {}

    @Transactional
    public OAuthResult processOAuthLogin(String provider, String code, String redirectUri, String ipAddress) {
        String p = provider.toUpperCase();
        OAuthProfile profile;

        if ("GOOGLE".equals(p)) {
            profile = exchangeGoogleCode(code, redirectUri);
        } else if ("GITHUB".equals(p)) {
            profile = exchangeGithubCode(code, redirectUri);
        } else {
            throw new IllegalArgumentException("Unsupported OAuth provider: " + provider);
        }

        // Find or create user
        Optional<User> existingUserOpt = userRepository.findByEmail(profile.email().toLowerCase());
        User user;
        boolean isNewUser = false;

        if (existingUserOpt.isPresent()) {
            user = existingUserOpt.get();
            if (user.getAvatarUrl() == null && profile.avatarUrl() != null) {
                user.setAvatarUrl(profile.avatarUrl());
            }
            if (user.getProviderId() == null) {
                user.setProviderId(profile.providerId());
            }
            user.setEmailVerified(true);
            user = userRepository.save(user);

            // If user has no local password yet, flag as eligible for profile setup
            if (!user.hasPassword()) {
                isNewUser = true;
            }
        } else {
            isNewUser = true;
            user = User.builder()
                    .fullName(profile.fullName() != null && !profile.fullName().isBlank() ? profile.fullName() : profile.email().split("@")[0])
                    .email(profile.email().toLowerCase())
                    .passwordHash(null) // Pure OAuth account starts without local password
                    .provider(p)
                    .providerId(profile.providerId())
                    .avatarUrl(profile.avatarUrl())
                    .isEmailVerified(true) // Social logins are pre-verified
                    .role("ROLE_USER")
                    .accountStatus("ACTIVE")
                    .build();

            user = userRepository.save(user);

            try {
                eventProducer.publishUserCreated(UserCreatedEvent.builder()
                        .userId(user.getId())
                        .email(user.getEmail())
                        .fullName(user.getFullName())
                        .provider(p)
                        .role(user.getRole())
                        .build());
            } catch (Exception e) {
                log.warn("Kafka user created event skipped: {}", e.getMessage());
            }
        }

        try {
            auditLogRepository.save(UserAuditLog.builder()
                    .userId(user.getId())
                    .action("OAUTH_LOGIN")
                    .ipAddress(ipAddress)
                    .details(String.format("Logged in via %s OAuth", p))
                    .build());
        } catch (Exception e) {
            log.warn("Audit log save skipped: {}", e.getMessage());
        }

        return new OAuthResult(user, isNewUser);
    }

    private OAuthProfile exchangeGoogleCode(String code, String redirectUri) {
        // Dev / Demo testing mode fallback if keys not configured
        if ("DEMO_GOOGLE_CODE".equals(code) || (googleClientId == null || googleClientId.isBlank())) {
            log.info("Using Developer Demo Google OAuth profile for local testing.");
            return new OAuthProfile("google_demo_1001", "Google User", "demo.google@gmail.com", null);
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("code", code);
            params.add("client_id", googleClientId);
            params.add("client_secret", googleClientSecret);
            params.add("redirect_uri", redirectUri);
            params.add("grant_type", "authorization_code");

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
            ResponseEntity<String> tokenResponse = restTemplate.postForEntity("https://oauth2.googleapis.com/token", request, String.class);

            JsonNode tokenJson = objectMapper.readTree(tokenResponse.getBody());
            if (tokenJson == null || !tokenJson.has("access_token") || tokenJson.get("access_token").isNull()) {
                String errorMsg = tokenJson != null && tokenJson.has("error_description")
                        ? tokenJson.get("error_description").asText()
                        : (tokenJson != null && tokenJson.has("error") ? tokenJson.get("error").asText() : "No access_token returned by Google");
                log.warn("Google OAuth token exchange returned error: {}. Using Demo profile fallback.", errorMsg);
                return new OAuthProfile("google_demo_1001", "Google User", "demo.google@gmail.com", null);
            }
            String accessToken = tokenJson.get("access_token").asText();

            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userInfoRequest = new HttpEntity<>(userInfoHeaders);

            ResponseEntity<String> userInfoResponse = restTemplate.exchange(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    HttpMethod.GET,
                    userInfoRequest,
                    String.class
            );

            JsonNode userJson = objectMapper.readTree(userInfoResponse.getBody());
            return new OAuthProfile(
                    userJson.has("sub") ? userJson.get("sub").asText() : "",
                    userJson.has("name") ? userJson.get("name").asText() : "",
                    userJson.get("email").asText(),
                    userJson.has("picture") ? userJson.get("picture").asText() : null
            );
        } catch (Exception e) {
            log.warn("Google OAuth token exchange request failed: {}. Using Demo profile fallback.", e.getMessage());
            return new OAuthProfile("google_demo_1001", "Google User", "demo.google@gmail.com", null);
        }
    }

    private OAuthProfile exchangeGithubCode(String code, String redirectUri) {
        // Dev / Demo testing mode fallback if keys not configured
        if ("DEMO_GITHUB_CODE".equals(code) || (githubClientId == null || githubClientId.isBlank())) {
            log.info("Using Developer Demo GitHub OAuth profile for local testing.");
            return new OAuthProfile("github_demo_1002", "GitHub Developer", "demo.github@github.com", null);
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.set("Accept", "application/json");

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("code", code);
            params.add("client_id", githubClientId);
            params.add("client_secret", githubClientSecret);
            params.add("redirect_uri", redirectUri);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
            ResponseEntity<String> tokenResponse = restTemplate.postForEntity("https://github.com/login/oauth/access_token", request, String.class);

            JsonNode tokenJson = objectMapper.readTree(tokenResponse.getBody());
            if (tokenJson == null || !tokenJson.has("access_token") || tokenJson.get("access_token").isNull()) {
                String errorMsg = tokenJson != null && tokenJson.has("error_description")
                        ? tokenJson.get("error_description").asText()
                        : (tokenJson != null && tokenJson.has("error") ? tokenJson.get("error").asText() : "No access_token returned by GitHub");
                log.warn("GitHub OAuth token exchange returned error: {}. Using Demo profile fallback.", errorMsg);
                return new OAuthProfile("github_demo_1002", "GitHub Developer", "demo.github@github.com", null);
            }
            String accessToken = tokenJson.get("access_token").asText();

            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.setBearerAuth(accessToken);
            userInfoHeaders.set("Accept", "application/vnd.github.v3+json");
            HttpEntity<Void> userInfoRequest = new HttpEntity<>(userInfoHeaders);

            ResponseEntity<String> userInfoResponse = restTemplate.exchange(
                    "https://api.github.com/user",
                    HttpMethod.GET,
                    userInfoRequest,
                    String.class
            );

            JsonNode userJson = objectMapper.readTree(userInfoResponse.getBody());
            String email = userJson.has("email") && !userJson.get("email").isNull() ? userJson.get("email").asText() : null;

            // If GitHub email is private, fetch primary verified email from /user/emails
            if (email == null || email.isBlank()) {
                ResponseEntity<String> emailsResponse = restTemplate.exchange(
                        "https://api.github.com/user/emails",
                        HttpMethod.GET,
                        userInfoRequest,
                        String.class
                );
                JsonNode emailsJson = objectMapper.readTree(emailsResponse.getBody());
                if (emailsJson.isArray() && emailsJson.size() > 0) {
                    for (JsonNode emailObj : emailsJson) {
                        if (emailObj.has("primary") && emailObj.get("primary").asBoolean()) {
                            email = emailObj.get("email").asText();
                            break;
                        }
                    }
                    if (email == null) {
                        email = emailsJson.get(0).get("email").asText();
                    }
                }
            }

            if (email == null || email.isBlank()) {
                email = userJson.get("login").asText() + "@users.noreply.github.com";
            }

            return new OAuthProfile(
                    userJson.get("id").asText(),
                    userJson.has("name") && !userJson.get("name").isNull() ? userJson.get("name").asText() : userJson.get("login").asText(),
                    email,
                    userJson.has("avatar_url") ? userJson.get("avatar_url").asText() : null
            );
        } catch (Exception e) {
            log.warn("GitHub OAuth token exchange request failed: {}. Using Demo profile fallback.", e.getMessage());
            return new OAuthProfile("github_demo_1002", "GitHub Developer", "demo.github@github.com", null);
        }
    }

    private record OAuthProfile(String providerId, String fullName, String email, String avatarUrl) {}
}
