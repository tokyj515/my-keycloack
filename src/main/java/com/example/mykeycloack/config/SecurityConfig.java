package com.example.mykeycloack.config;

import com.example.mykeycloack.keycloak.CustomGrantedAuthoritiesMapper;
import com.example.mykeycloack.keycloak.KeycloakService;
import java.util.Collection;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  private final KeycloakService keycloakService;

  private final CustomAccessDeniedHandler accessDeniedHandler;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
        new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
//    oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8000/oauth2/authorization/keycloak");//"{baseUrl}/home"
    oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8000/logout-success");

    CustomGrantedAuthoritiesMapper authoritiesMapper = new CustomGrantedAuthoritiesMapper(keycloakService);

    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin").hasAuthority("ROLE_LV1") // 관리자 접근
            .requestMatchers("/user").authenticated()       // 인증된 사용자
            .requestMatchers("/", "/register", "/home", "/logout", "/css/**", "/js/**", "/api/users/save-from-token").permitAll() // 공용 리소스
            .anyRequest().authenticated()                  // 나머지 요청 인증 필요
        )
        .exceptionHandling(exceptions -> exceptions
            .accessDeniedHandler(accessDeniedHandler) // Custom AccessDeniedHandler 등록
        )
        .oauth2Login(oauth2 -> oauth2
            .loginPage("/oauth2/authorization/keycloak")
            .defaultSuccessUrl("/home", true)
            .userInfoEndpoint(userInfo -> userInfo
                .userAuthoritiesMapper(authorities -> {
                  return authorities.stream()
                      .map(authority -> {
                        if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                          return new SimpleGrantedAuthority("ROLE_" + oidcUserAuthority.getAttributes().get("preferred_username"));
                        }
                        return authority;
                      })
                      .toList(); // Stream을 List로 변환
                })
            )
        )
        .logout(logout -> logout
            .logoutUrl("/logout") // 로그아웃 엔드포인트
            .logoutSuccessHandler(oidcLogoutSuccessHandler)
        );
    return http.build();
  }
}
//http://localhost:8000/oauth2/authorization/keycloak