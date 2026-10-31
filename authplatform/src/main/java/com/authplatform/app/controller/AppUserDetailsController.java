package com.authplatform.app.controller;

import com.authplatform.app.dto.AppDtos;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.audit.AuditLog;
import com.authplatform.audit.AuditQueryService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.dto.PageResult;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.common.security.AuthenticatedPrincipal;
import com.authplatform.role.service.RoleService;
import com.authplatform.sa.dto.SaDtos;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AppUserRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Detail view used by the console user-management workflow. */
@RestController
@RequestMapping({"/api/console/apps/{appId}/users/{userId}", "/api/sa/apps/{appId}/users/{userId}"})
public class AppUserDetailsController {
  private final AppRepository apps;
  private final AppUserRepository users;
  private final RoleService roles;
  private final AuditQueryService auditQueries;
  private final SessionService sessions;

  public AppUserDetailsController(
      AppRepository apps,
      AppUserRepository users,
      RoleService roles,
      AuditQueryService auditQueries,
      SessionService sessions) {
    this.apps = apps;
    this.users = users;
    this.roles = roles;
    this.auditQueries = auditQueries;
    this.sessions = sessions;
  }

  @GetMapping("/details")
  AppDtos.AppUserDetailsView details(
      @PathVariable UUID appId, @PathVariable UUID userId, Authentication authentication) {
    authorize(appId, authentication);
    AppUser user =
        users
            .findByAppIdAndId(appId, userId)
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    AppDtos.AppUserView view =
        new AppDtos.AppUserView(
            user.getId(),
            user.getAppId(),
            user.getName(),
            user.getEmail(),
            user.isEmailVerified(),
            user.getStatus(),
            user.getLastLoginAt(),
            user.getCreatedAt(),
            user.isInvited());
    var userRoles = roles.userRoles(appId, userId).roles();
    var userRolePermissions = roles.userRolePermissions(appId, userId);
    var effectivePermissions =
        userRolePermissions.stream()
            .flatMap(role -> role.permissionKeys().stream())
            .distinct()
            .sorted()
            .toList();
    return new AppDtos.AppUserDetailsView(
        view,
        userRoles,
        userRolePermissions,
        effectivePermissions);
  }

  /** The same searchable, paged history as the SA audit log, limited to this user's events. */
  @GetMapping("/activity")
  PageResult<SaDtos.AuditLogView> activity(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @RequestParam(defaultValue = "") String q,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      Authentication authentication) {
    authorizeUser(appId, userId, authentication);
    return PageResult.of(
        auditQueries.search(q, userId, page, size).map(AppUserDetailsController::auditView));
  }

  private static SaDtos.AuditLogView auditView(AuditLog log) {
    return new SaDtos.AuditLogView(
        log.getId(),
        log.getAppId(),
        log.getActorAccountId(),
        log.getActorAppUserId(),
        log.getActorType(),
        log.getAction(),
        log.getIpAddress(),
        log.getRequestId(),
        log.getCreatedAt(),
        log.getMetadata());
  }

  @GetMapping("/sessions")
  List<SessionService.SessionView> sessions(
      @PathVariable UUID appId, @PathVariable UUID userId, Authentication authentication) {
    authorizeUser(appId, userId, authentication);
    return sessions.appUserSessions(userId, null);
  }

  @DeleteMapping("/sessions/{sessionId}")
  ResponseEntity<Void> revokeSession(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @PathVariable UUID sessionId,
      Authentication authentication) {
    authorizeUser(appId, userId, authentication);
    sessions.revokeAppUserSession(userId, sessionId);
    return ResponseEntity.noContent().build();
  }

  @DeleteMapping("/sessions")
  ResponseEntity<Void> revokeAllSessions(
      @PathVariable UUID appId, @PathVariable UUID userId, Authentication authentication) {
    authorizeUser(appId, userId, authentication);
    sessions.revokeAllForAppUser(userId);
    return ResponseEntity.noContent().build();
  }

  private void authorizeUser(UUID appId, UUID userId, Authentication authentication) {
    authorize(appId, authentication);
    if (users.findByAppIdAndId(appId, userId).isEmpty())
      throw new ApiException(ErrorCode.NOT_FOUND);
  }

  private void authorize(UUID appId, Authentication authentication) {
    boolean sa =
        authentication != null
            && authentication.getAuthorities().stream()
                .anyMatch(value -> "ROLE_SA".equals(value.getAuthority()));
    if (sa) {
      if (!apps.existsById(appId)) throw new ApiException(ErrorCode.NOT_FOUND);
      return;
    }
    Object principal = authentication == null ? null : authentication.getPrincipal();
    if (!(principal instanceof AuthenticatedPrincipal authenticated)
        || apps.findByIdAndOwnerAccountId(appId, authenticated.subjectId()).isEmpty()) {
      throw new ApiException(ErrorCode.ACCESS_DENIED);
    }
  }
}
