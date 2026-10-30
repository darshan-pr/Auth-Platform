package com.authplatform.auth.controller;

import com.authplatform.app.entity.App;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.auth.security.AppKeyAuthenticationFilter;
import com.authplatform.auth.service.AccountAuthService;
import com.authplatform.auth.service.AppUserAuthService;
import com.authplatform.common.security.AuthenticatedPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MfaController {
  private final AccountAuthService accounts;
  private final AppUserAuthService appUsers;

  public MfaController(AccountAuthService accounts, AppUserAuthService appUsers) {
    this.accounts = accounts;
    this.appUsers = appUsers;
  }

  @GetMapping("/api/console/mfa/status")
  MfaDtos.Status consoleStatus(@AuthenticationPrincipal AuthenticatedPrincipal principal) {
    return accounts.mfaStatus(principal.subjectId());
  }

  @GetMapping("/api/sa/mfa/status")
  MfaDtos.Status saStatus(@AuthenticationPrincipal AuthenticatedPrincipal principal) {
    return accounts.mfaStatus(principal.subjectId());
  }

  @GetMapping("/api/v1/auth/mfa/status")
  MfaDtos.Status appUserStatus(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @AuthenticationPrincipal AuthenticatedPrincipal principal) {
    return appUsers.mfaStatus(app.getId(), principal.subjectId());
  }
}
