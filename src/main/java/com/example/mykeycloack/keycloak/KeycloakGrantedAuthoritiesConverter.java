package com.example.mykeycloack.keycloak;

import java.util.List;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.stream.Collectors;

public class KeycloakGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

  @Override
  public Collection<GrantedAuthority> convert(Jwt jwt) {
    // Keycloak의 Access Token에서 permissions 정보 추출
    var permissions = (Collection<String>) jwt.getClaims().get("permissions");
    if (permissions == null) {
      return List.of();
    }

    // permissions를 Spring Security 권한으로 변환
    return permissions.stream()
        .map(permission -> new SimpleGrantedAuthority(permission))
        .collect(Collectors.toList());
  }
}
