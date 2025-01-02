package com.example.mykeycloack.config;

import com.example.mykeycloack.keycloak.CustomGrantedAuthoritiesMapper;
import com.example.mykeycloack.keycloak.KeycloakLogoutHandler;
import com.example.mykeycloack.keycloak.KeycloakService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  private final KeycloakService keycloakService;
  private final CustomAccessDeniedHandler accessDeniedHandler;
  private final OAuth2AuthorizedClientService authorizedClientService;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
        new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
    oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8000/logout-success");

    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin").hasAuthority("ROLE_LV1") // 관리자만 접근 가능
            .requestMatchers("/user").authenticated() // 인증된 사용자만 접근 가능
            .anyRequest().permitAll() // 나머지는 모두 접근 가능
        )
        .oauth2Login(oauth2 -> oauth2
            .loginPage("/oauth2/authorization/keycloak") // Keycloak 로그인 페이지
            .defaultSuccessUrl("/home", true) // 로그인 성공 후 홈 화면으로 리다이렉트
        )
        .logout(logout -> logout
            .logoutUrl("/logout") // 로그아웃 URL
            .logoutSuccessHandler(oidcLogoutSuccessHandler) // 로그아웃 후 리다이렉트
            .invalidateHttpSession(true) // 세션 무효화
            .deleteCookies("JSESSIONID") // 세션 쿠키 삭제
        )
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요한 경우에만 세션 생성
            .maximumSessions(1) // 최대 1개의 세션만 허용
            .expiredUrl("/session-expired") // 세션 만료 시 이동할 URL
        );

    return http.build();
  }

}

//http://localhost:8000/oauth2/authorization/keycloak