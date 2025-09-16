package com.my131.oidc_study.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

@Service
@Slf4j
public class IdTokenService {
    public boolean validateIdToken(OidcIdToken idToken, String expectedClientId) {
        try {
            if (idToken.getExpiresAt().isBefore(Instant.now())) {
                log.warn("ID Token이 만료됨: exp={}", idToken.getExpiresAt());
                return false;
            }

            assert idToken.getIssuedAt() != null;
            if (idToken.getIssuedAt().isAfter(Instant.now())) {
                log.warn("ID Token이 미래에 발급됨: iat={}", idToken.getIssuedAt());
                return false;
            }

            if (!idToken.getAudience().contains(expectedClientId)) {
                log.warn("ID Token의 audience가 일치하지 않음: expected={}, actual={}", expectedClientId, idToken.getAudience());
                return false;
            }

            if (!"https://accounts.google.com".equals(idToken.getIssuer().toString())) {
                log.warn("ID Token의 issuer가 일치하지 않음: {}", idToken.getIssuer());
                return false;
            }

            log.info("ID Token 검증 성공: sub={}, iss={}", idToken.getSubject(), idToken.getIssuer());
            return true;
        } catch (Exception e) {
            log.error("ID Token 검증 중 오류 발생", e);
            return false;
        }
    }

    public Map<String, Object> extractUserInfo(OidcIdToken idToken) {
        log.info("ID Token에서 사용자 정보 추출: {}", idToken.getSubject());

        Map<String, Object> claims = idToken.getClaims();

        log.info("추출된 사용자 정보 - sub: {}, name: {}, email_verified: {}",
                claims.get("sub"),
                claims.get("name"),
                claims.get("email_verified"));

        return claims;
    }

    public Jwt decodeIdToken(String idTokenValue) {
        try {
            log.info("ID Token 디코딩 시작");

            String[] parts = idTokenValue.split("\\.");
            if (parts.length != 3) {
                throw new JwtException("유효하지 않은 JWT 형식");
            }

            log.info("JWT 구조 확인 완료: header.payload.signature");
            return null;
        } catch (Exception e) {
            log.error("ID Token 디코딩 실패", e);
            throw new JwtException("ID Token 디코딩 실패", e);
        }
    }

    public void analyzeIdTokenClaims(OidcIdToken idToken) {
        log.info("=== ID Token 클레임 분석 ===");

        Map<String, Object> claims = idToken.getClaims();

        // 필수 클레임
        log.info("필수 클레임:");
        log.info("  iss (발급자): {}", claims.get("iss"));
        log.info("  sub (사용자ID): {}", claims.get("sub"));
        log.info("  aud (대상): {}", claims.get("aud"));
        log.info("  exp (만료시간): {}", claims.get("exp"));
        log.info("  iat (발급시간): {}", claims.get("iat"));

        // 프로필 클레임
        log.info("프로필 클레임:");
        log.info("  name: {}", claims.get("name"));
        log.info("  given_name: {}", claims.get("given_name"));
        log.info("  family_name: {}", claims.get("family_name"));
        log.info("  picture: {}", claims.get("picture"));
        log.info("  locale: {}", claims.get("locale"));

        // 이메일 클레임
        log.info("이메일 클레임:");
        log.info("  email: {}", claims.get("email"));
        log.info("  email_verified: {}", claims.get("email_verified"));

        log.info("=== 클레임 분석 완료 ===");
    }
}