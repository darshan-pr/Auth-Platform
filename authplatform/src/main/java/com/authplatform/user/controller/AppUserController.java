package com.authplatform.user.controller;

import com.authplatform.app.entity.App;
import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.security.AppKeyAuthenticationFilter;
import com.authplatform.auth.service.AppUserAuthService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.common.security.AuthenticatedPrincipal;
import com.authplatform.role.service.RoleService;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
public class AppUserController {
  private final AppUserAuthService service;
  private final RoleService roles;
  private final SessionService sessions;

  public AppUserController(AppUserAuthService service, RoleService roles, SessionService sessions) {
    this.service = service;
    this.roles = roles;
    this.sessions = sessions;
  }

  @GetMapping("/me")
  AuthDtos.UserSummary me(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @AuthenticationPrincipal AuthenticatedPrincipal principal) {
    var user = service.current(app.getId(), principal.subjectId());
    return new AuthDtos.UserSummary(
        user.getId(),
        user.getName(),
        user.getEmail(),
        user.isEmailVerified(),
        roles.roleNames(app.getId(), user.getId()),
        roles.permissionKeys(app.getId(), user.getId()));
  }

  @GetMapping("/me/sessions")
  List<SessionService.SessionView> sessions(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @AuthenticationPrincipal AuthenticatedPrincipal principal) {
    requireAppUserSession(app, principal);
    return sessions.appUserSessions(principal.subjectId(), principal.sessionId());
  }

  @DeleteMapping("/me/sessions/{sessionId}")
  ResponseEntity<Void> revokeSession(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @PathVariable UUID sessionId) {
    requireAppUserSession(app, principal);
    sessions.revokeAppUserSession(principal.subjectId(), sessionId);
    return ResponseEntity.noContent().build();
  }

  private void requireAppUserSession(App app, AuthenticatedPrincipal principal) {
    if (principal == null || !principal.appUser() || !app.getId().equals(principal.appId()))
      throw new ApiException(ErrorCode.ACCESS_DENIED);
  }
}
