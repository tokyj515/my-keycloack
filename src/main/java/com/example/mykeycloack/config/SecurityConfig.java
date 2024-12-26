package com.example.mykeycloack.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin").hasAuthority("ADMIN") // 관리자 접근
                        .requestMatchers("/user").authenticated() // 인증된 사용자
                        .requestMatchers("/realms/**").permitAll() // Keycloak API 허용
                        .requestMatchers("/", "/register", "/home", "/css/**", "/js/**").permitAll() // 공용 리소스
                        .anyRequest().authenticated() // 나머지 요청 인증 필요
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwkSetUri("http://localhost:8080/realms/my-realm/protocol/openid-connect/certs")
                        )
                );
        return http.build();
    }
}
