package com.my131.oidc_study.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {
    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {

            response.put("authenticated", true);
            response.put("type", "OIDC");
            response.put("subject", oidcUser.getSubject());
            response.put("name", oidcUser.getFullName());
            response.put("email", oidcUser.getEmail());
            response.put("picture", oidcUser.getPicture());
            response.put("emailVerified", oidcUser.getEmailVerified());
            response.put("authorities", authentication.getAuthorities());
        } else {
            response.put("authenticated", false);
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/id-token/claims")
    public ResponseEntity<Map<String, Object>> getIdTokenClaims(Authentication authentication) {
        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            return ResponseEntity.ok(oidcUser.getIdToken().getClaims());
        }

        return ResponseEntity.ok(Map.of("error", "OIDC 사용자가 아님"));
    }

    @GetMapping("/id-token/info")
    public ResponseEntity<Map<String, Object>> getIdTokenInfo(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            var idToken = oidcUser.getIdToken();

            response.put("tokenValue", idToken.getTokenValue());
            response.put("issuer", idToken.getIssuer().toString());
            response.put("subject", idToken.getSubject());
            response.put("audience", idToken.getAudience());
            response.put("expiresAt", idToken.getExpiresAt());
            response.put("issuedAt", idToken.getIssuedAt());
            response.put("authenticatedAt", idToken.getAuthenticatedAt());

            // 토큰 만료 여부
            assert idToken.getExpiresAt() != null;
            response.put("isExpired", idToken.getExpiresAt().isBefore(java.time.Instant.now()));

            return ResponseEntity.ok(response);
        }

        return ResponseEntity.ok(Map.of("error", "OIDC 사용자가 아님"));
    }

    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> getUserInfo(Authentication authentication) {
        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            return ResponseEntity.ok(oidcUser.getAttributes());
        }

        return ResponseEntity.ok(Map.of("error", "OIDC 사용자가 아님"));
    }

}