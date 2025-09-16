package com.my131.oidc_study.config;

import com.my131.oidc_study.service.CustomOidcUserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomOidcUserService customOidcUserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/", "/login", "/error", "/favicon.ico").permitAll()
                                .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                                .requestMatchers("/api/id-token/**").authenticated()
                                .anyRequest().authenticated()
                )
                .oauth2Login(
                        oauth -> oauth
                                .loginPage("/login")
                                .userInfoEndpoint( userInfo -> userInfo.oidcUserService(customOidcUserService))
                                .successHandler(oidcAuthenticationSuccessHandler())
                                .failureUrl("/login?error=true")
                )
                .logout(
                        logout -> logout
                                .logoutUrl("/logout")
                                .logoutSuccessUrl("/")
                                .invalidateHttpSession(true)
                                .clearAuthentication(true)
                                .deleteCookies("JSESSIONID")
                )
                .build();
    }

    @Bean
    public AuthenticationSuccessHandler oidcAuthenticationSuccessHandler  () {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                log.info("OIDC 인증 성공!");
                log.info("인증 타입: {}", authentication.getClass().getSimpleName());
                log.info("Principal 타입: {}", authentication.getPrincipal().getClass().getSimpleName());

                response.sendRedirect("/dashboard");
            }
        };
    }
}
