package com.example.mykeycloack.keycloak;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class CustomGrantedAuthoritiesMapper {

  public Collection<? extends GrantedAuthority> mapAuthoritiesFromClaims(Map<String, Object> claims) {
    Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");

    if (realmAccess != null && realmAccess.containsKey("roles")) {
      List<String> roles = (List<String>) realmAccess.get("roles");
      roles.forEach(role -> System.out.println("Mapped Role: ROLE_" + role));
      return roles.stream()
          .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
          .collect(Collectors.toList());
    }

    return List.of();
  }
}