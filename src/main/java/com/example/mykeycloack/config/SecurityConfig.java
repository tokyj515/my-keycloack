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
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화 (테스트 환경에서만)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin").hasAuthority("ADMIN") // 관리자 페이지 접근
                        .requestMatchers("/user").authenticated() // 사용자 페이지 접근
                        .requestMatchers("/", "/register", "/home", "/css/**", "/js/**").permitAll() // 공용 페이지 접근
                        .anyRequest().denyAll() // 나머지 요청 거부
                )
                .formLogin(form -> form
                        .disable() // 기본 폼 로그인 비활성화
                )
//                .formLogin(form -> form
//                        .loginPage("/login") // 커스텀 로그인 페이지
////                        .defaultSuccessUrl("/home", true) // 로그인 성공 후 리디렉션
////                        .failureUrl("/login?error=true") // 로그인 실패 시
//                        .permitAll()
//                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login") // 로그아웃 성공 후 리디렉션
//                        .invalidateHttpSession(true)
                        .permitAll()
                );
        return http.build();
    }
}

