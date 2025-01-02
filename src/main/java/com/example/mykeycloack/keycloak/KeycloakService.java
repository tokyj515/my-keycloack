package com.example.mykeycloack.keycloak;

import com.example.mykeycloack.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class KeycloakService {

    private final RestTemplate restTemplate;

    private final String KEYCLOAK_URL = "http://localhost:8080";
    private final String REALM = "my-realm";
    private final String ADMIN_CLIENT_ID = "custom-admin-cli";
    private final String ADMIN_CLIENT_SECRET = "ghodSzOHfjqowuX5M11IA0G4h7DyVNTi";


    /**
     * Access Token에서 역할(Role) 추출
     * @param accessToken Keycloak에서 발급된 Access Token
     * @return 역할 리스트
     */
    public List<String> extractRolesFromToken(String accessToken) {
        try {
            Claims claims = Jwts.parserBuilder()
                .build()
                .parseClaimsJws(accessToken)
                .getBody();

            Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
            return (List<String>) realmAccess.get("roles");
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse roles from Access Token", e);
        }
    }
}
