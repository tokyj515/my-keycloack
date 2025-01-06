package com.example.mykeycloack;

import com.example.mykeycloack.keycloak.KeycloakService;
import com.example.mykeycloack.user.User;
import com.example.mykeycloack.user.UserService;
import jakarta.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.List;
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

    @GetMapping("/home")
    public String home(Authentication authentication, Model model, HttpSession session) {
        if (authentication != null) {
            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                model.addAttribute("username", oidcUser.getName());
            }

            // Access Token 가져오기
            OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient("keycloak", authentication.getName());

            if (authorizedClient != null) {
                String accessToken = authorizedClient.getAccessToken().getTokenValue();
                model.addAttribute("accessToken", accessToken);

                // 세션에 Access Token 저장
                session.setAttribute("accessToken", accessToken);

                // 만료 시간 계산
                if (authorizedClient.getAccessToken().getExpiresAt() != null) {
                    long expiresAt = authorizedClient.getAccessToken().getExpiresAt().toEpochMilli(); // 만료 시각
                    long currentTime = System.currentTimeMillis(); // 현재 시각
                    int remainingTimeInSeconds = (int) ((expiresAt - currentTime) / 1000);

                    // 만료 시간 최소 값 설정
                    if (remainingTimeInSeconds < 0) {
                        remainingTimeInSeconds = 1; // 최소 1초로 설정
                    }
                    model.addAttribute("sessionExpiryTime", remainingTimeInSeconds);
                    System.out.println("Access Token Expiry Time: " + remainingTimeInSeconds + " seconds");
                } else {
                    model.addAttribute("sessionExpiryTime", 0);
                }

                // Access Token 클레임 파싱
                Map<String, Object> claims = keycloakService.parseJwtClaims(accessToken);
                if (claims.containsKey("realm_access")) {
                    Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
                    if (realmAccess.containsKey("roles")) {
                        List<String> roles = (List<String>) realmAccess.get("roles");
                        List<String> processedRoles = roles.stream().toList();
                        session.setAttribute("roles", processedRoles);
                    }
                }
            }
        }
        return "home";
    }


    @PostMapping("/refresh-token")
    public String refreshToken(HttpSession session, Authentication authentication) {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient("keycloak", authentication.getName());

        if (client != null) {
            String refreshToken = client.getRefreshToken().getTokenValue();
            String newAccessToken = keycloakService.refreshAccessToken(refreshToken);
            session.setAttribute("accessToken", newAccessToken);
            return "redirect:/home";
        }

        return "redirect:/logout";
    }

    @GetMapping("/logout-success")
    public String logout() {
        return "logout-success";
    }

    @GetMapping("/session-expired")
    public String sessionExpired() {
        return "session-expired"; // 세션 만료 화면
    }

    @GetMapping("/admin")
    public String admin(Authentication authentication, HttpSession session, Model model) {
        if (authentication != null && authentication.isAuthenticated()) {
            model.addAttribute("username", authentication.getName());

            // 세션에서 Access Token 가져오기
            String accessToken = (String) session.getAttribute("accessToken");
            if (accessToken != null) {
                System.out.println("Access Token from Session: " + accessToken);

                // Access Token 디코딩 및 클레임 확인
                Map<String, Object> claims = keycloakService.parseJwtClaims(accessToken);
                System.out.println("Access Token Claims: " + claims);
            }
        }
        return "admin"; // 관리자 템플릿
    }


    @GetMapping("/user")
    public String userPage() {
        return "user";
    }

    // 세션 정보 출력
    @GetMapping("/session-info")
    public String sessionInfo(HttpSession session, Authentication authentication, Model model) {
        // 세션 ID
        model.addAttribute("sessionId", session.getId());

        // 인증 정보
        if (authentication != null) {
            model.addAttribute("username", authentication.getName());
            model.addAttribute("authorities", authentication.getAuthorities());
        }

        // 세션 속성들
        Map<String, Object> sessionAttributes = new HashMap<>();
        session.getAttributeNames().asIterator().forEachRemaining(attr -> {
            sessionAttributes.put(attr, session.getAttribute(attr));
        });
        model.addAttribute("sessionAttributes", sessionAttributes);

        return "session-info"; // 템플릿 이름
    }

}
