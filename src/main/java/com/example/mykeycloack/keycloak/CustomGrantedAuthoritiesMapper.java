package com.example.mykeycloack.keycloak;

import java.util.ArrayList;
import java.util.Arrays;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class CustomGrantedAuthoritiesMapper {

  public Collection<? extends GrantedAuthority> mapAuthoritiesFromClaims(Map<String, Object> claims) {
    List<GrantedAuthority> authorities = new ArrayList<>();

    // Access Token의 "realm_access.roles" 추출
    if (claims.containsKey("realm_access")) {
      Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
      if (realmAccess.containsKey("roles")) {
        List<String> roles = (List<String>) realmAccess.get("roles");
        roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
      }
    }

    // 추가 권한 정보가 필요한 경우 처리
    if (claims.containsKey("scope")) {
      String scope = (String) claims.get("scope");
      Arrays.stream(scope.split(" ")).forEach(s -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + s)));
    }

    return authorities;
  }
}
