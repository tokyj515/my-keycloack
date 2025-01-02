package com.example.mykeycloack.keycloak;

import java.util.Map;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

  /**
   * Access Token 디코딩
   *
   * @param accessToken Keycloak에서 발급된 Access Token
   * @return 디코딩된 클레임(Map 형태)
   */
  public Map<String, Object> decodeAccessToken(String accessToken) {
    Claims claims = Jwts.parserBuilder()
        .build()
        .parseClaimsJws(accessToken)
        .getBody();

    return claims;
  }
}