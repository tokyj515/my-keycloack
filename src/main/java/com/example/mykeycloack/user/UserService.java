package com.example.mykeycloack.user;

import com.example.mykeycloack.keycloak.KeycloakService;
import com.example.mykeycloack.user.User;
import com.example.mykeycloack.user.UserRepository;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final KeycloakService keycloakService;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    public User registerUser(User user) {
        // 1. 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        user.setRole("cli-admin");

        // 2. 데이터베이스에 사용자 저장
        User savedUser = userRepository.save(user);

        // 3. Keycloak에 사용자 추가 요청
        keycloakService.saveUserToKeycloak(user);

        // 4. Keycloak에서 사용자 역할 매핑 (수정된 부분)
        if (user.getRole() != null) {
            keycloakService.assignClientRoleToUser(user.getUsername(),"my-service-client2", user.getRole());
        }


        return savedUser; // 저장된 사용자 반환
    }

    public String loginUser(User user, HttpSession session) {
        try {
            System.out.println("서비스단:" + user.getUsername() + " "+ user.getPassword());

            // Keycloak에서 액세스 토큰 요청
            String accessToken = keycloakService.getUserAccessToken(user.getUsername(), user.getPassword());

            System.out.println("로그인: " +accessToken);

            // 세션에 사용자 정보 및 액세스 토큰 저장
            session.setAttribute("username", user.getUsername());
            session.setAttribute("accessToken", accessToken);

            return accessToken; // 성공적으로 발급된 액세스 토큰 반환
        } catch (Exception e) {
            throw new RuntimeException("로그인 실패: " + e.getMessage(), e);
        }
    }


}
