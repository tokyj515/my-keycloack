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
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/register", "/css/**", "/js/**").permitAll() // 공용 접근 허용
                        .requestMatchers("/admin").hasRole("ADMIN") // 관리자 페이지는 관리자만 접근
                        .requestMatchers("/user").authenticated() // 사용자 페이지는 인증 필요
                        .anyRequest().denyAll() // 나머지는 접근 금지
                )
                .formLogin(form -> form
                        .loginPage("/login") // 커스텀 로그인 페이지
                        .defaultSuccessUrl("/") // 로그인 성공 시 홈으로 이동
                        .failureUrl("/") // 로그인 실패 시 홈으로 이동
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/") // 로그아웃 성공 시 홈으로 이동
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login") // OAuth2 로그인 페이지
                        .defaultSuccessUrl("/") // 로그인 성공 시 홈으로 이동
                );
        return http.build();
    }
}
