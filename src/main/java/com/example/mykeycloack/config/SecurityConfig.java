package com.example.mykeycloack.config;

import com.example.mykeycloack.keycloak.CustomGrantedAuthoritiesMapper;
import com.example.mykeycloack.keycloak.KeycloakService;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
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
    oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8000/logout-success");

    CustomGrantedAuthoritiesMapper authoritiesMapper = new CustomGrantedAuthoritiesMapper();

    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin").hasAuthority("ROLE_LV1") // 관리자 접근
            .requestMatchers("/user").authenticated()          // 인증된 사용자
            .requestMatchers("/", "/register", "/home", "/logout", "/css/**", "/js/**", "/api/users/save-from-token").permitAll() // 공용 리소스
            .anyRequest().authenticated()                      // 나머지 요청 인증 필요
        )
        .exceptionHandling(exceptions -> exceptions
            .accessDeniedHandler(accessDeniedHandler) // Custom AccessDeniedHandler 등록
        )
        .oauth2Login(oauth2 -> oauth2
            .loginPage("/oauth2/authorization/keycloak")
            .defaultSuccessUrl("/home", true) // 로그인 성공 후 리디렉션
            .userInfoEndpoint(userInfo -> userInfo
                .userAuthoritiesMapper(authorities -> {
                  return authorities.stream()
                      .flatMap(authority -> {
                        if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                          // CustomGrantedAuthoritiesMapper를 활용하여 권한 매핑
                          return authoritiesMapper
                              .mapAuthorities(oidcUserAuthority.getAttributes())
                              .stream();
                        }
                        // 기본 Authority 반환
                        return Stream.of(authority);
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