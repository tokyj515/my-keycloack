package com.example.mykeycloack.config;

import com.example.mykeycloack.keycloak.KeycloakGrantedAuthoritiesConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        // CSRF 비활성화 (필요에 따라 활성화 가능)
        .csrf(csrf -> csrf.disable())

        // 요청별 권한 설정
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin/**").hasAuthority("LV1") // Keycloak Permission 기반
            .requestMatchers("/user").authenticated() // 인증된 사용자만 접근 가능
            .anyRequest().permitAll() // 나머지 요청은 모두 허용
        )

        // JWT를 통한 인증 처리
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwtAuthenticationConverter(jwtAuthenticationConverter()) // Access Token 권한 변환
            )
        )

        // OAuth2 로그인 설정
        .oauth2Login(oauth2 -> oauth2
            .loginPage("/oauth2/authorization/keycloak") // Keycloak 로그인 페이지
            .defaultSuccessUrl("/home", true) // 로그인 성공 후 홈으로 리다이렉트
        )

        // 로그아웃 설정
        .logout(logout -> logout
            .logoutUrl("/logout") // 로그아웃 URL
            .invalidateHttpSession(true) // 세션 무효화
            .deleteCookies("JSESSIONID") // 세션 쿠키 삭제
            .logoutSuccessUrl("/logout-success") // 로그아웃 후 리다이렉트
        )

        // 세션 관리
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요한 경우에만 세션 생성
            .maximumSessions(1) // 최대 1개의 세션만 허용
            .expiredUrl("/session-expired") // 세션 만료 시 이동할 URL
        );

    return http.build();
  }

  // JWT에서 Keycloak 권한 정보 추출
  private JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(new KeycloakGrantedAuthoritiesConverter());
    return converter;
  }
}

//http://localhost:8000/oauth2/authorization/keycloak