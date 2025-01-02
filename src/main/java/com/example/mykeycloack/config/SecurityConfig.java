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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
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
import org.springframework.web.client.RestTemplate;

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

    // Keycloak Logout Handler 설정
    KeycloakLogoutHandler keycloakLogoutHandler = new KeycloakLogoutHandler(
        "http://localhost:8080/realms/myrealm/protocol/openid-connect/logout"
    );

    http
        .csrf(csrf -> csrf.disable()) // CSRF 비활성화
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin").hasAuthority("ROLE_LV1") // "/admin" 경로는 ROLE_LV1 권한 필요
            .requestMatchers("/user").authenticated() // "/user" 경로는 인증된 사용자만 접근 가능
            .requestMatchers("/", "/register", "/home", "/logout", "/css/**", "/js/**", "/api/users/save-from-token").permitAll() // 공용 리소스
            .anyRequest().authenticated() // 나머지 모든 요청은 인증 필요
        )
        .exceptionHandling(exceptions -> exceptions
            .accessDeniedHandler(accessDeniedHandler) // 커스텀 Access Denied Handler
        )
        .oauth2Login(oauth2 -> oauth2
            .loginPage("/oauth2/authorization/keycloak") // Keycloak 로그인 페이지로 이동
            .defaultSuccessUrl("/home", true) // 로그인 성공 시 홈 화면으로 리다이렉트
            .failureUrl("/login-failed") // 로그인 실패 시 실패 화면으로 리다이렉트
            .userInfoEndpoint(userInfo -> userInfo
                .userAuthoritiesMapper(authorities -> {
                  Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                  if (authentication instanceof OAuth2AuthenticationToken authToken) {
                    OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                        authToken.getAuthorizedClientRegistrationId(),
                        authToken.getName()
                    );

                    if (authorizedClient != null) {
                      String accessToken = authorizedClient.getAccessToken().getTokenValue();
                      Map<String, Object> claims = keycloakService.parseJwtClaims(accessToken);

                      // Keycloak User Info Endpoint 호출
                      Map<String, Object> userInfos = fetchUserInfoFromKeycloak(accessToken);
                      System.out.println("User Info: " + userInfos);

                      // 필요하면 유저 정보와 권한 매핑 로직 추가
                      return new CustomGrantedAuthoritiesMapper().mapAuthoritiesFromClaims(claims);
                    }
                  }
                  return authorities; // 기본 권한 반환
                })
            )
        )
        .logout(logout -> logout
            .logoutUrl("/logout") // 애플리케이션의 로그아웃 경로
            .addLogoutHandler(keycloakLogoutHandler) // Keycloak과 연동하여 로그아웃 처리
            .logoutSuccessHandler(oidcLogoutSuccessHandler) // 로그아웃 성공 후 처리
            .invalidateHttpSession(true) // 세션 무효화
            .deleteCookies("JSESSIONID") // JSESSIONID 쿠키 삭제
        )
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요한 경우에만 세션 생성
            .sessionFixation().changeSessionId() // 새 세션 ID로 교체
            .maximumSessions(1) // 한 번에 한 명만 로그인 가능
            .maxSessionsPreventsLogin(true) // 추가 로그인 차단
            .expiredUrl("/session-expired") // 세션 만료 시 리다이렉트 경로
        );

    return http.build();
  }


  private Map<String, Object> fetchUserInfoFromKeycloak(String accessToken) {
    RestTemplate restTemplate = new RestTemplate();

    // Keycloak User Info Endpoint URL
    String userInfoEndpoint = "http://localhost:8080/realms/{realm}/protocol/openid-connect/userinfo";

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(accessToken); // Bearer Access Token 설정
    HttpEntity<String> entity = new HttpEntity<>(headers);

    try {
      ResponseEntity<Map> response = restTemplate.exchange(
          userInfoEndpoint,
          HttpMethod.POST,
          entity,
          Map.class
      );

      return response.getBody(); // User Info 데이터 반환
    } catch (Exception e) {
      e.printStackTrace();
      return Map.of(); // 에러 발생 시 빈 Map 반환
    }
  }

}

//http://localhost:8000/oauth2/authorization/keycloak