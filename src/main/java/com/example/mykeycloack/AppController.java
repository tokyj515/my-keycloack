package com.example.mykeycloack;

import com.example.mykeycloack.keycloak.KeycloakService;
import com.example.mykeycloack.user.User;
import com.example.mykeycloack.user.UserService;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
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

    /**
     * **"keycloak"**은 Spring Security의 클라이언트 등록 식별자입니다. 그대로 사용하세요.
     * Access Token을 가져오지 못하는 문제는 설정이 아닌 인증 흐름이나 Keycloak 설정에서 발생했을 가능성이 높습니다.
     * 로그를 통해 Access Token 발급 과정과 Spring Security 내부 동작을 점검하세요. 문제가 계속되면 관련 로그를 공유해 주시면 추가로 도와드릴 수 있습니다!
     * */

    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        if (authentication != null) {
            System.out.println("Authorities: " + authentication.getAuthorities());
            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                model.addAttribute("username", oidcUser.getName());
            }

            // Access Token 가져오기
            OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(
                    "keycloak", // 클라이언트 등록 ID
                    authentication.getName()
                );
            if (authorizedClient != null) {
                String accessToken = authorizedClient.getAccessToken().getTokenValue();
                model.addAttribute("accessToken", accessToken);

                Map<String, Object> claims = keycloakService.parseJwtClaims(accessToken);
                System.out.println("Access Token Claims: " + claims);
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