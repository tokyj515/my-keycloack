package com.example.mykeycloack;

import com.example.mykeycloack.keycloak.KeycloakService;
import com.example.mykeycloack.user.User;
import com.example.mykeycloack.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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


    // 홈 화면
    @GetMapping("/home")
    public String home(Model model, @RequestParam(required = false) String username) {
        // 인증된 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            model.addAttribute("username", authentication.getName()); // Spring Security를 통해 사용자 이름 설정
        } else {
            model.addAttribute("username", username); // URL에서 전달된 사용자 이름
        }
        return "home";
    }

    // 회원가입 페이지
    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User()); // User 객체 초기화
        return "register";
    }


    // 회원가입 처리
    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user, Model model) {
        // User 객체를 KeycloakService에 전달
        User savedUser = userService.registerUser(user);

        return "redirect:/home"; // 회원가입 완료 후 홈으로 리디렉션
    }

    // 로그인 페이지
    @GetMapping("/login")
    public String loginPage() {
        return "login";
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