package com.authplatform.common.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CsrfController {
  @GetMapping({"/api/console/csrf", "/api/sa/csrf"})
  CsrfTokenResponse csrfToken(CsrfToken csrfToken) {
    return new CsrfTokenResponse(csrfToken.getToken());
  }

  record CsrfTokenResponse(String token) {}
}
