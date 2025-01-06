package com.example.mykeycloack.keycloak;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class CustomAuthorizationFilter extends OncePerRequestFilter {

  private final OAuth2AuthorizedClientService authorizedClientService;
  private final KeycloakService keycloakService;

  public CustomAuthorizationFilter(OAuth2AuthorizedClientService authorizedClientService, KeycloakService keycloakService) {
    this.authorizedClientService = authorizedClientService;
    this.keycloakService = keycloakService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication instanceof OAuth2AuthenticationToken authToken) {
      OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
          authToken.getAuthorizedClientRegistrationId(),
          authToken.getName()
      );

      if (authorizedClient != null) {
        // Access Token 가져오기
        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        Map<String, Object> claims = keycloakService.parseJwtClaims(accessToken);

        // roles 추출 및 GrantedAuthority 생성
        if (claims.containsKey("realm_access")) {
          Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
          if (realmAccess.containsKey("roles")) {
            List<String> roles = (List<String>) realmAccess.get("roles");
            List<SimpleGrantedAuthority> authorities = roles.stream()
//                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toList());

            // 새로운 Authentication 객체 생성 및 SecurityContext 설정
            Authentication newAuth = new OAuth2AuthenticationToken(
                authToken.getPrincipal(),
                authorities,
                authToken.getAuthorizedClientRegistrationId()
            );
            SecurityContextHolder.getContext().setAuthentication(newAuth);
          }
        }
      }
    }

    filterChain.doFilter(request, response);
  }
}
