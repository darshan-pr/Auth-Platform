package com.authplatform.auth.controller;

import com.authplatform.auth.service.JwtService;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {
  private final JwtService service;

  public JwksController(JwtService service) {
    this.service = service;
  }

  @GetMapping("/.well-known/jwks.json")
  ResponseEntity<JWKSet> jwks() {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.maxAge(java.time.Duration.ofHours(1)).cachePublic())
        .body(service.jwks());
  }
}
