package com.example.mykeycloack.keycloak;


import com.example.mykeycloack.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;


@Service
@RequiredArgsConstructor
public class KeycloakService {

    private final RestTemplate restTemplate;

    public String getAdminAccessToken() {
        String keycloakUrl = "http://localhost:8080/realms/my-realm/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", "custom-admin-cli");
        body.add("client_secret", "ZjVN2V4luwHHXs28Fc4ii0N746CgRgww");
        body.add("grant_type", "client_credentials");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(keycloakUrl, request, Map.class);

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        } else {
            throw new RuntimeException("Failed to retrieve access token: " + response.getBody());
        }
    }

    public void saveUserToKeycloak(User user) {
        String keycloakUrl = "http://localhost:8080/admin/realms/my-realm/users";
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

        ResponseEntity<String> response = restTemplate.postForEntity(keycloakUrl, request, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to save user to Keycloak: " + response.getBody());
        }
    }


}
