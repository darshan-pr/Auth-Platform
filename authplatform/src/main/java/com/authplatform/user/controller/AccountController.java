package com.authplatform.user.controller;

import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.service.AccountAuthService;
import com.authplatform.common.security.AuthenticatedPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/console")
public class AccountController {
  private final AccountAuthService service;

  public AccountController(AccountAuthService service) {
    this.service = service;
  }

  @GetMapping("/me")
  AuthDtos.AccountSummary me(@AuthenticationPrincipal AuthenticatedPrincipal principal) {
    var account = service.current(principal.subjectId());
    return new AuthDtos.AccountSummary(
        account.getId(), account.getName(), account.getEmail(), account.getPlatformRole().name());
  }
}
