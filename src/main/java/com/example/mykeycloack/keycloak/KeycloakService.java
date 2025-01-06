package com.example.mykeycloack.keycloak;

import com.example.mykeycloack.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.util.Base64;
import java.util.HashMap;
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

    // Keycloak 토큰 엔드포인트 URL (Keycloak 설정에 따라 변경)
    private final String tokenEndpoint = "http://localhost:8080/realms/my-realm/protocol/openid-connect/token";

    // Keycloak 클라이언트 정보
    private final String clientId = "my-service-client2";
    private final String clientSecret = "d6eglWPWDxwU0suWHPvgIqLY8zVb53rS";


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


    public Map<String, Object> parseJwtClaims(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length == 3) {
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                ObjectMapper objectMapper = new ObjectMapper();
                return objectMapper.readValue(payload, Map.class);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Map.of();
    }



//    public String refreshAccessToken(String refreshToken) {
//        HttpHeaders headers = new HttpHeaders();
//        headers.setBasicAuth(clientId, clientSecret);  // 클라이언트 인증
//
//        Map<String, String> body = new HashMap<>();
//        body.put("grant_type", "refresh_token");
//        body.put("refresh_token", refreshToken);
//
//        HttpEntity<Map<String, String>> requestEntity = new HttpEntity<>(body, headers);
//
//        ResponseEntity<Map> response = restTemplate.exchange(
//            tokenEndpoint,
//            HttpMethod.POST,
//            requestEntity,
//            Map.class
//        );
//
//        // 새 Access Token 반환
//        Map<String, Object> responseBody = response.getBody();
//        assert responseBody != null;
//        return (String) responseBody.get("access_token");
//    }

    public String refreshAccessToken(String refreshToken) {
        String tokenEndpoint = "http://localhost:8080/realms/my-realm/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");  // 필수 파라미터
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(tokenEndpoint, HttpMethod.POST, requestEntity, String.class);

        return response.getBody();
    }
}
