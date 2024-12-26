package com.example.mykeycloack.keycloak;

import com.example.mykeycloack.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class KeycloakService {

    private final RestTemplate restTemplate;

    /**
     * Keycloak에서 Admin Access Token을 가져오는 메서드.
     */
    public String getAdminAccessToken() {
        String keycloakUrl = "http://localhost:8080/realms/my-realm/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", "custom-admin-cli");
        body.add("client_secret", "ghodSzOHfjqowuX5M11IA0G4h7DyVNTi");
        body.add("grant_type", "client_credentials");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(keycloakUrl, request, Map.class);

        System.out.println("Request Body: " + body);
        System.out.println("Request Headers: " + headers);


        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        } else {
            throw new RuntimeException("Failed to retrieve access token: " + response.getBody());
        }
    }

    /**
     * Keycloak에 새로운 사용자를 저장하는 메서드.
     */
    public void saveUserToKeycloak(User user) {
        String keycloakUrl = "http://localhost:8080/admin/realms/my-realm/users";
        String accessToken = getAdminAccessToken();
        System.out.println("accessToken: " + accessToken);

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

        ResponseEntity<String> response = restTemplate.postForEntity(keycloakUrl, request, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to save user to Keycloak: " + response.getBody());
        }
    }

    /**
     * Keycloak 사용자에게 역할(Role)을 할당하는 메서드.
     */
    public void assignClientRoleToUser(String username, String clientId, String roleName) {
        // 사용자 ID 조회
        String userId = getUserId(username);

        // 역할 ID 조회
        String roleId = getClientRoleId(clientId, roleName);

        // Keycloak API URL
        String keycloakUrl = String.format(
                "http://localhost:8080/admin/realms/my-realm/users/%s/role-mappings/clients/%s",
                userId, getClientId(clientId)
        );

        String accessToken = getAdminAccessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);

        // 역할 정보 JSON
        String body = """
            [
                {
                    "id": "%s",
                    "name": "%s"
                }
            ]
            """.formatted(roleId, roleName);

        HttpEntity<String> request = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(keycloakUrl, request, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to assign client role to user: " + response.getBody());
        }
    }

    /**
     * Keycloak에서 클라이언트 역할(Client Role) ID를 조회하는 메서드.
     */
    private String getClientRoleId(String clientId, String roleName) {
        String keycloakUrl = String.format(
                "http://localhost:8080/admin/realms/my-realm/clients/%s/roles/%s",
                getClientId(clientId), roleName
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                keycloakUrl, HttpMethod.GET, request, Map.class
        );

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return (String) response.getBody().get("id");
        } else {
            throw new RuntimeException("Client role not found in Keycloak: " + roleName);
        }
    }

    /**
     * Keycloak에서 클라이언트 ID를 조회하는 메서드.
     */
    private String getClientId(String clientId) {
        String keycloakUrl = "http://localhost:8080/admin/realms/my-realm/clients?clientId=" + clientId;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<List> response = restTemplate.exchange(
                keycloakUrl, HttpMethod.GET, request, List.class
        );

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty()) {
            Map<String, Object> client = (Map<String, Object>) response.getBody().get(0);
            return (String) client.get("id");
        } else {
            throw new RuntimeException("Failed to fetch client ID from Keycloak for clientId: " + clientId);
        }
    }

//    public void assignRoleToUser(String username, String roleName) {
//        // 사용자 ID 조회
//        String userId = getUserId(username);
//
//        // 역할 ID 조회
//        String roleId = getRoleId(roleName);
//
//        // Keycloak API URL
//        String keycloakUrl = String.format(
//                "http://localhost:8080/admin/realms/my-realm/users/%s/role-mappings/realm",
//                userId
//        );
//
//        String accessToken = getAdminAccessToken();
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_JSON);
//        headers.setBearerAuth(accessToken);
//
//        // 역할 정보 JSON
//        String body = """
//    [
//        {
//            "id": "%s",
//            "name": "%s"
//        }
//    ]
//    """.formatted(roleId, roleName);
//
//        HttpEntity<String> request = new HttpEntity<>(body, headers);
//
//        ResponseEntity<String> response = restTemplate.postForEntity(keycloakUrl, request, String.class);
//
//        if (!response.getStatusCode().is2xxSuccessful()) {
//            throw new RuntimeException("Failed to assign role to user: " + response.getBody());
//        }
//    }



    public String getRoleId(String roleName) {
        String keycloakUrl = "http://localhost:8080/admin/realms/my-realm/roles/%s".formatted(roleName);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                keycloakUrl, HttpMethod.GET, request, Map.class
        );

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return (String) response.getBody().get("id");
        } else {
            throw new RuntimeException("Role not found in Keycloak: " + roleName);
        }
    }

    /**
     * Keycloak에서 사용자 ID를 조회하는 메서드.
     */
    private String getUserId(String username) {
        // Keycloak REST API URL: 사용자 이름으로 사용자 조회
        String keycloakUrl = "http://localhost:8080/admin/realms/my-realm/users?username=" + username;

        // Access Token 가져오기
        String accessToken = getAdminAccessToken();

        // HTTP 요청 헤더 설정
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        // Keycloak API 호출
        ResponseEntity<List> response = restTemplate.exchange(
                keycloakUrl, HttpMethod.GET, request, List.class
        );

        // 응답 확인 및 사용자 ID 반환
        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty()) {
            // 사용자 객체의 첫 번째 항목에서 ID를 추출
            Map<String, Object> user = (Map<String, Object>) response.getBody().get(0);
            return (String) user.get("id");
        } else {
            throw new RuntimeException("Failed to fetch user ID from Keycloak for username: " + username);
        }
    }


    // 유저 정보를 활용해서 키클록에서 액세스 토큰 갖고 오기
    public String getUserAccessToken(String username, String password) {
        String keycloakUrl = "http://localhost:8080/realms/my-realm/protocol/openid-connect/token";

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", "my-service-client2");
        params.add("client_secret", "d6eglWPWDxwU0suWHPvgIqLY8zVb53rS");
        params.add("username", username);
        params.add("password", password);
//        params.add("scope", "openid profile email");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(keycloakUrl, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> responseBody = response.getBody();
                if (responseBody != null) {
                    return responseBody.get("access_token").toString();
                }
            } else {
                throw new RuntimeException("Unexpected response: " + response.getStatusCode());
            }
        } catch (HttpClientErrorException e) {
            throw new RuntimeException("Invalid credentials or unauthorized request: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException("Failed to get access token: " + e.getMessage());
        }

        return null;
    }


}
