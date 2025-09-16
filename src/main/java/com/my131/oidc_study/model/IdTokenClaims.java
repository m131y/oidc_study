package com.my131.oidc_study.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
public class IdTokenClaims {
    // 필수 클레임
    private String issuer;              // iss
    private String subject;             // sub
    private String audience;            // aud
    private Instant expiresAt;          // exp
    private Instant issuedAt;           // iat
    private Instant authTime;           // auth_time

    // 프로필 클레임
    private String name;
    private String givenName;
    private String familyName;
    private String middleName;
    private String nickname;
    private String preferredUsername;
    private String profile;
    private String picture;
    private String website;
    private String gender;
    private String birthdate;
    private String zoneinfo;
    private String locale;
    private Instant updatedAt;

    // 이메일 클레임
    private String email;
    private Boolean emailVerified;

    // 주소 클레임
    private Map<String, Object> address;

    // 전체 클레임
    private Map<String, Object> allClaims;

    // ID Token 값
    private String tokenValue;

    // 편의 메서드
    public String getDisplayName() {
        if (name != null) return name;
        if (givenName != null && familyName != null) {
            return givenName + " " + familyName;
        }
        return preferredUsername != null ? preferredUsername : subject;
    }

    public String getProfileImage() {
        return picture != null ? picture : "/images/default-profile.png";
    }

    public boolean isTokenExpired() {
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }
}