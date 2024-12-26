package com.example.mykeycloack;

import com.example.mykeycloack.keycloak.KeycloakService;
import com.example.mykeycloack.user.User;
import com.example.mykeycloack.user.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
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
        System.out.println("savedUser: " + savedUser.toString());
        return "redirect:/home"; // 회원가입 완료 후 홈으로 리디렉션
    }

    // 로그인 페이지
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }


    //로컬 스토리지에 저장해서 헤더에 넣어오기

    @PostMapping("/login")
    public String loginUser(
            @ModelAttribute User user, HttpSession session, Model model) {
        try {
            // UserService를 통해 로그인 처리
            String accessToken = userService.loginUser(user, session);

            // 로그인 성공 시 홈으로 리디렉션
            return "redirect:/home";
        } catch (Exception e) {
            // 로그인 실패 시 에러 메시지 설정 및 로그인 페이지로 이동
            model.addAttribute("error", "Invalid login credentials.");
            return "login";
        }
    }


    @GetMapping("/home")
    public String home(Model model, @RequestParam(required = false) String username) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            model.addAttribute("username", authentication.getName());
        } else {
            model.addAttribute("username", username);
        }
        return "home";
    }




//    @GetMapping("/home")
//    public String home(HttpSession session, Model model) {
//        // 세션에서 사용자 정보와 액세스 토큰 가져오기
//        String username = (String) session.getAttribute("username");
//        String accessToken = (String) session.getAttribute("accessToken");
//
//        if (username != null && accessToken != null) {
//            model.addAttribute("username", username);
//            model.addAttribute("accessToken", accessToken);
//        } else {
//            model.addAttribute("username", null);
//            model.addAttribute("accessToken", null);
//        }
//
//        return "home"; // 홈 뷰 렌더링
//    }
//

//    // 홈 화면 -> post 로그인이랑 다른 액세스 토큰을 가질 수 있어서 일단은 세션 방식으로 진행
// 로그인 처리
//    @PostMapping("/login")
//    public String loginUser(@RequestParam String username, @RequestParam String password, Model model) {
//        try {
//            // Keycloak을 통해 액세스 토큰 가져오기
//            String accessToken = keycloakService.getUserAccessToken(username, password);
//            model.addAttribute("accessToken", accessToken);
//            model.addAttribute("username", username);
//            return "redirect:/home?username=" + username; // 홈 화면으로 리디렉션, 사용자 이름 전달
//        } catch (Exception e) {
//            model.addAttribute("error", "Invalid login credentials.");
//            return "login";
//        }
//    }
//    @GetMapping("/home")
//    public String home(Model model, @RequestParam(required = false) String username) {
//        // 인증된 사용자 정보 가져오기
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getName())) {
//            model.addAttribute("username", authentication.getName()); // Spring Security를 통해 사용자 이름 설정
//            model.addAttribute("accessToken", keycloakService.getUserAccessToken(authentication.getName(), null)); // 토큰 추가
//        } else {
//            model.addAttribute("username", username); // URL에서 전달된 사용자 이름
//        }
//        return "home";
//    }





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