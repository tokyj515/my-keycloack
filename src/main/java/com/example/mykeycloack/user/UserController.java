package com.example.mykeycloack.user;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

  private final UserService userService;

  /**
   * Access Token을 기반으로 사용자 정보 저장
   *
   * @param accessToken 클라이언트로부터 전달받은 Access Token
   * @return 저장 성공 메시지
   */
  @PostMapping("/save-from-token")
  public ResponseEntity<String> saveUserFromToken(@RequestBody String accessToken) {
    userService.saveUserFromToken(accessToken);
    return ResponseEntity.ok("User information saved successfully!");
  }
}