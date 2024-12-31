package com.example.mykeycloack;

import com.example.mykeycloack.keycloak.KeycloakService;
import com.example.mykeycloack.user.User;
import com.example.mykeycloack.user.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class AppController {

    private final KeycloakService keycloakService;
    private final UserService userService;

    private final OAuth2AuthorizedClientService authorizedClientService;


//    // 회원가입 페이지
//    @GetMapping("/register")
//    public String showRegistrationForm(Model model) {
//        model.addAttribute("user", new User()); // User 객체 초기화
//        return "register";
//    }
//
//
//    // 회원가입 처리
//    @PostMapping("/register")
//    public String registerUser(@ModelAttribute User user, Model model) {
//        // User 객체를 KeycloakService에 전달
//        User savedUser = userService.registerUser(user);
//        System.out.println("savedUser: " + savedUser.toString());
//        return "redirect:/home"; // 회원가입 완료 후 홈으로 리디렉션
//    }
//
//    // 로그인 페이지
//    @GetMapping("/login")
//    public String loginPage() {
//        return "login";
//    }
//
//
//    //로컬 스토리지에 저장해서 헤더에 넣어오기
//
//    @PostMapping("/login")
//    public String loginUser(
//            @ModelAttribute User user, HttpSession session, Model model) {
//        try {
//            // UserService를 통해 로그인 처리
//            String accessToken = userService.loginUser(user, session);
//
//            // 로그인 성공 시 홈으로 리디렉션
//            return "redirect:/home";
//        } catch (Exception e) {
//            // 로그인 실패 시 에러 메시지 설정 및 로그인 페이지로 이동
//            model.addAttribute("error", "Invalid login credentials.");
//            return "login";
//        }
//    }


//    @GetMapping("/home")
//    public String home(Model model, @RequestParam(required = false) String username) {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        if (authentication != null && authentication.isAuthenticated()
//                && !(authentication instanceof AnonymousAuthenticationToken)) {
//            model.addAttribute("username", authentication.getName());
//        } else {
//            model.addAttribute("username", username);
//        }
//        return "home";
//    }

    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        // 사용자 이름 추가
        if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            model.addAttribute("username", oidcUser.getName());
        }

        // Access Token 가져오기
        if (authentication != null && authentication.getPrincipal() != null) {
            OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(
                    "my-service-client2", // 등록된 클라이언트 ID와 동일해야 함
                    authentication.getName()
                );
            if (authorizedClient != null) {
                String accessToken = authorizedClient.getAccessToken().getTokenValue();
                model.addAttribute("accessToken", accessToken);
            }
        }

        return "home"; // Thymeleaf 템플릿 이름
    }

    @GetMapping("/logout-success")
    public String logout() {
        return "logout-success";
    }


    // 관리자 페이지
    @GetMapping("/admin")
    public String adminPage() {
        return "admin";
    }

    // 사용자 페이지
    @GetMapping("/user")
    public String userPage() {
        return "user";
    }
}