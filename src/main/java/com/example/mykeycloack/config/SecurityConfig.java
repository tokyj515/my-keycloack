package com.example.mykeycloack.config;

import com.example.mykeycloack.keycloak.CustomGrantedAuthoritiesMapper;
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

    CustomGrantedAuthoritiesMapper authoritiesMapper = new CustomGrantedAuthoritiesMapper();

    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin").hasAuthority("ROLE_LV1")
            .requestMatchers("/user").authenticated()
            .requestMatchers("/", "/register", "/home", "/logout", "/css/**", "/js/**", "/api/users/save-from-token").permitAll()
            .anyRequest().authenticated()
        )
        .exceptionHandling(exceptions -> exceptions
            .accessDeniedHandler(accessDeniedHandler)
        )
        .oauth2Login(oauth2 -> oauth2
            .loginPage("/oauth2/authorization/keycloak")
            .defaultSuccessUrl("/home", true)
            .userInfoEndpoint(userInfo -> userInfo
                .userAuthoritiesMapper(authorities -> {
                  // CustomGrantedAuthoritiesMapper 사용
                  Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                  if (authentication instanceof OAuth2AuthenticationToken authToken) {
                    OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                        authToken.getAuthorizedClientRegistrationId(),
                        authToken.getName()
                    );

                    if (authorizedClient != null) {
                      String accessToken = authorizedClient.getAccessToken().getTokenValue();
                      Map<String, Object> claims = keycloakService.parseJwtClaims(accessToken);

                      System.out.println("시큐리티: " + accessToken);

                      // CustomGrantedAuthoritiesMapper로 권한 매핑
                      return new CustomGrantedAuthoritiesMapper().mapAuthoritiesFromClaims(claims);
                    }
                  }
                  return authorities;
                })
            )
        )

        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutSuccessHandler(oidcLogoutSuccessHandler)
        );
    return http.build();
  }

  private Map<String, Object> parseJwtClaims(String token) {
    try {
      String[] parts = token.split("\\.");
      if (parts.length == 3) {
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(payload, Map.class);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return Map.of();
  }
}

//http://localhost:8000/oauth2/authorization/keycloak