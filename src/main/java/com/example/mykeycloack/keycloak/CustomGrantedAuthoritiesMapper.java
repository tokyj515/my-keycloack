package com.example.mykeycloack.keycloak;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class CustomGrantedAuthoritiesMapper {

  private final KeycloakService keycloakService;

  public CustomGrantedAuthoritiesMapper(KeycloakService keycloakService) {
    this.keycloakService = keycloakService;
  }


  public Collection<? extends GrantedAuthority> mapAuthorities(OidcUser oidcUser) {
    String accessToken = oidcUser.getIdToken().getTokenValue();
    List<String> roles = keycloakService.extractRolesFromToken(accessToken);

    // Keycloak의 Roles를 Spring Security의 GrantedAuthority로 변환
    return roles.stream()
        .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // 예: "ROLE_LV1"
        .toList();
  }
}