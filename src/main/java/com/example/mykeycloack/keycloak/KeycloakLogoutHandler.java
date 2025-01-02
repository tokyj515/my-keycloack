package com.example.mykeycloack.keycloak;

import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.core.Authentication;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class KeycloakLogoutHandler implements LogoutHandler {

  private final String keycloakLogoutUrl;

  public KeycloakLogoutHandler(String keycloakLogoutUrl) {
    this.keycloakLogoutUrl = keycloakLogoutUrl;
  }

  @Override
  public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    try {
      // Keycloak 로그아웃 URL로 리다이렉트
      response.sendRedirect(keycloakLogoutUrl);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
