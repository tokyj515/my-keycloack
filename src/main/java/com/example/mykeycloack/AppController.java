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



    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            model.addAttribute("username", oidcUser.getName());

            // Access Token 가져오기
            OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(
                    "keycloak", // 클라이언트 등록 ID
                    authentication.getName()
                );

            if (authorizedClient != null) {
                String accessToken = authorizedClient.getAccessToken().getTokenValue();
                System.out.println("Access Token: " + accessToken); // 디버깅용
                model.addAttribute("accessToken", accessToken);
            } else {
                System.out.println("Authorized Client is null");
            }
        }
        return "home";
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