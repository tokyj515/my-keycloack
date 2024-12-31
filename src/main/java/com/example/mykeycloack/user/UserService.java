package com.example.mykeycloack.user;

import com.example.mykeycloack.keycloak.KeycloakService;
import com.example.mykeycloack.keycloak.TokenService;
import jakarta.servlet.http.HttpSession;
import java.util.List;
import java.util.Map;
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
    private final TokenService tokenService;



    /**
     * Access Token을 기반으로 사용자 정보를 저장
     *
     * @param accessToken Keycloak에서 발급된 Access Token
     */
    public void saveUserFromToken(String accessToken) {
        // 1. Access Token을 사용해 Keycloak에서 사용자 정보 요청
        Map<String, Object> userInfo = keycloakService.getUserInfoFromToken(accessToken);

        System.out.println("User Info: " + userInfo);

        // 2. 사용자 정보 추출
        String username = (String) userInfo.get("preferred_username");
        String email = (String) userInfo.get("email");
        String name = (String) userInfo.get("name");
        List<String> roles = (List<String>) ((Map<String, Object>) userInfo.get("realm_access")).get("roles");

        // 3. 사용자 DB 저장
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setRole(String.join(",", roles)); // 여러 Role일 경우 ','로 연결
        userRepository.save(user);
    }



    /**
     * 회원가입 처리
     */
//    @Transactional
//    public User registerUser(User user) {
//        // 1. 비밀번호 암호화
//        String encodedPassword = passwordEncoder.encode(user.getPassword());
//        user.setPassword(encodedPassword);
//        user.setRole("LV1"); // 기본 Role 설정
//
//        // 2. 내부 데이터베이스에 사용자 저장
//        User savedUser = userRepository.save(user);
//
//        // 3. Keycloak에 사용자 추가
//        keycloakService.saveUserToKeycloak(user);
//
//        // 4. Keycloak에서 기본 Role 할당
//        keycloakService.assignClientRoleToUser(user.getUsername(), "my-service-client2", "LV1");
//
//        return savedUser;
//    }

    /**
     * 로그인 처리
     */
//    public String loginUser(User user, HttpSession session) {
//        try {
//            // Keycloak에서 액세스 토큰 요청
//            String accessToken = keycloakService.getUserAccessToken(user.getUsername(), user.getPassword());
//
//            // 세션에 사용자 정보 저장
//            session.setAttribute("username", user.getUsername());
//            session.setAttribute("accessToken", accessToken);
//
//            return accessToken;
//        } catch (Exception e) {
//            throw new RuntimeException("로그인 실패: " + e.getMessage(), e);
//        }
//    }
}
