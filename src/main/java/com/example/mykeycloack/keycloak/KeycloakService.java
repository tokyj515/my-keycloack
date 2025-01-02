package com.example.mykeycloack.keycloak;

import com.example.mykeycloack.user.User;
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
     * Keycloak에서 Admin Access Token 가져오기
     */
    public String getAdminAccessToken() {
        String url = KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", ADMIN_CLIENT_ID);
        body.add("client_secret", ADMIN_CLIENT_SECRET);
        body.add("grant_type", "client_credentials");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        } else {
            throw new RuntimeException("Failed to retrieve admin access token.");
        }
    }

    /**
     * Keycloak에 사용자 추가
     */
    public void saveUserToKeycloak(User user) {
        String url = KEYCLOAK_URL + "/admin/realms/" + REALM + "/users";
        String accessToken = getAdminAccessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);

        String body = """
        {
            "username": "%s",
            "email": "%s",
            "enabled": true,
            "credentials": [
                {
                    "type": "password",
                    "value": "%s",
                    "temporary": false
                }
            ]
        }
        """.formatted(user.getUsername(), user.getEmail(), user.getPassword());

        HttpEntity<String> request = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to save user to Keycloak.");
        }
    }

    /**
     * Keycloak 사용자에 Role 할당
     */
    public void assignClientRoleToUser(String username, String clientId, String roleName) {
        String userId = getUserId(username);
        String roleId = getClientRoleId(clientId, roleName);

        String url = KEYCLOAK_URL + "/admin/realms/" + REALM + "/users/" + userId + "/role-mappings/clients/" + getClientId(clientId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(getAdminAccessToken());

        String body = """
        [
            {
                "id": "%s",
                "name": "%s"
            }
        ]
        """.formatted(roleId, roleName);

        HttpEntity<String> request = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to assign role to user in Keycloak.");
        }
    }

    private String getUserId(String username) {
        String url = KEYCLOAK_URL + "/admin/realms/" + REALM + "/users?username=" + username;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty()) {
            Map<String, Object> user = (Map<String, Object>) response.getBody().get(0);
            return (String) user.get("id");
        } else {
            throw new RuntimeException("Failed to fetch user ID from Keycloak.");
        }
    }

    private String getClientId(String clientId) {
        String url = KEYCLOAK_URL + "/admin/realms/" + REALM + "/clients?clientId=" + clientId;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty()) {
            Map<String, Object> client = (Map<String, Object>) response.getBody().get(0);
            return (String) client.get("id");
        } else {
            throw new RuntimeException("Failed to fetch client ID from Keycloak.");
        }
    }

    private String getClientRoleId(String clientId, String roleName) {
        String url = KEYCLOAK_URL + "/admin/realms/" + REALM + "/clients/" + getClientId(clientId) + "/roles/" + roleName;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return (String) response.getBody().get("id");
        } else {
            throw new RuntimeException("Failed to fetch role ID from Keycloak.");
        }
    }

//    public String getUserAccessToken(String username, String password) {
//        String url = KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/token";
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//
//        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
//        body.add("client_id", "my-service-client2");
//        body.add("client_secret", "d6eglWPWDxwU0suWHPvgIqLY8zVb53rS");
//        body.add("grant_type", "password");
//        body.add("username", username);
//        body.add("password", password);
//
//        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
//
//        ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
//        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
//            return (String) response.getBody().get("access_token");
//        } else {
//            throw new RuntimeException("Failed to fetch user access token.");
//        }
//    }

    public Map<String, Object> getUserInfoFromToken(String accessToken) {
        String userInfoUrl = "http://localhost:8080/realms/my-realm/protocol/openid-connect/userinfo";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
            userInfoUrl,
            HttpMethod.GET,
            request,
            Map.class
        );

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to fetch user info: " + response.getBody());
        }

        return response.getBody();
    }

}
