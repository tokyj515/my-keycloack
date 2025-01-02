package com.example.mykeycloack.keycloak;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CustomGrantedAuthoritiesMapper {

  public Collection<? extends GrantedAuthority> mapAuthorities(Map<String, Object> attributes) {
    Map<String, Object> realmAccess = (Map<String, Object>) attributes.get("realm_access");

    if (realmAccess != null && realmAccess.containsKey("roles")) {
      System.out.println("Realm Access: " + realmAccess);

      List<String> roles = (List<String>) realmAccess.get("roles");

      // 매핑된 롤 출력
      roles.forEach(role -> System.out.println("Mapped Role: ROLE_" + role));

      // Keycloak의 Roles를 Spring Security의 GrantedAuthority로 변환
      return roles.stream()
          .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // ROLE_ 접두사 추가
          .collect(Collectors.toList());
    }

    // roles가 없으면 빈 리스트 반환
    return List.of();
  }
}
