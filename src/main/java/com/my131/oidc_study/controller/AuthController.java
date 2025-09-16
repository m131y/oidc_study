package com.my131.oidc_study.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {
    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated() && !authentication.getPrincipal().equals("anonymousUser")) {
            model.addAttribute("isLoggedIn", true);

            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                model.addAttribute("username", oidcUser.getFullName());
            }
        } else {
            model.addAttribute("isLoggedIn", false);
        }
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            model.addAttribute("user", oidcUser);
            model.addAttribute("subject", oidcUser.getSubject());
            model.addAttribute("name", oidcUser.getFullName());
            model.addAttribute("email", oidcUser.getEmail());
            model.addAttribute("picture", oidcUser.getPicture());
            model.addAttribute("emailVerified", oidcUser.getEmailVerified());

            var idToken = oidcUser.getIdToken();
            model.addAttribute("idToken", idToken);
            model.addAttribute("idTokenValue", idToken.getTokenValue());
            model.addAttribute("issuer", idToken.getIssuer());
            model.addAttribute("audience", idToken.getAudience());
            model.addAttribute("expiresAt", idToken.getExpiresAt());
            model.addAttribute("issuedAt", idToken.getIssuedAt());

            var userInfo = oidcUser.getUserInfo();
            if (userInfo != null) {
                model.addAttribute("userInfo", userInfo.getClaims());
            }
            model.addAttribute("allClaims", oidcUser.getClaims());
        }
        return "dashboard";
    }
}
