package com.authplatform.auth.controller;

import com.authplatform.auth.service.SessionService;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.common.security.AuthenticatedPrincipal;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/console/sessions", "/api/sa/sessions"})
public class SessionController {
  private final SessionService sessions;

  public SessionController(SessionService sessions) {
    this.sessions = sessions;
  }

  @GetMapping
  List<SessionService.SessionView> sessions(
      @AuthenticationPrincipal AuthenticatedPrincipal principal) {
    requireAccount(principal);
    return sessions.accountSessions(principal.subjectId(), principal.sessionId());
  }

  @DeleteMapping("/{sessionId}")
  ResponseEntity<Void> revoke(
      @AuthenticationPrincipal AuthenticatedPrincipal principal, @PathVariable UUID sessionId) {
    requireAccount(principal);
    sessions.revokeAccountSession(principal.subjectId(), sessionId);
    return ResponseEntity.noContent().build();
  }

  private void requireAccount(AuthenticatedPrincipal principal) {
    if (principal == null || principal.appUser()) throw new ApiException(ErrorCode.ACCESS_DENIED);
  }
}
