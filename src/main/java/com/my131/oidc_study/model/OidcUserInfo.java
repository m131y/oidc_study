package com.my131.oidc_study.model;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
public class OidcUserInfo {
    private String provider;
    private Instant loginTime;

    // ID Token에서 추출한 정보
    private IdTokenClaims idTokenClaims;

    // UserInfo에서 추출한 추가 정보
    private Map<String, Object> userInfoClaims;

    // 통합된 사용자 정보
    private String userId;
    private String name;
    private String email;
    private String picture;
    private Boolean emailVerified;

    public static OidcUserInfo from(String provider, OidcUser oidcUser) {
        return OidcUserInfo.builder()
                .provider(provider)
                .loginTime(Instant.now())
                .idTokenClaims(extractIdTokenClaims(oidcUser))
                .userInfoClaims(extractUserInfoClaims(oidcUser))
                .userId(oidcUser.getSubject())
                .name(oidcUser.getFullName())
                .email(oidcUser.getEmail())
                .picture(oidcUser.getPicture())
                .emailVerified(oidcUser.getEmailVerified())
                .build();
    }

    private static IdTokenClaims extractIdTokenClaims(OidcUser oidcUser) {
        var idToken = oidcUser.getIdToken();
        var claims = idToken.getClaims();

        return IdTokenClaims.builder()
                .issuer(idToken.getIssuer().toString())
                .subject(idToken.getSubject())
                .audience(idToken.getAudience().toString())
                .expiresAt(idToken.getExpiresAt())
                .issuedAt(idToken.getIssuedAt())
                .authTime(idToken.getAuthenticatedAt())
                .name((String) claims.get("name"))
                .givenName((String) claims.get("given_name"))
                .familyName((String) claims.get("family_name"))
                .email((String) claims.get("email"))
                .emailVerified((Boolean) claims.get("email_verified"))
                .picture((String) claims.get("picture"))
                .locale((String) claims.get("locale"))
                .allClaims(claims)
                .tokenValue(idToken.getTokenValue())
                .build();
    }
    private static Map<String, Object> extractUserInfoClaims(OidcUser oidcUser) {
        org.springframework.security.oauth2.core.oidc.OidcUserInfo userInfo = oidcUser.getUserInfo();
        return userInfo != null ? userInfo.getClaims() : null;
    }
}