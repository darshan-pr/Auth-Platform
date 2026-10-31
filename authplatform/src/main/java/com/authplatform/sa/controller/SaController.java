package com.authplatform.sa.controller;

import com.authplatform.common.security.AuthenticatedPrincipal;
import com.authplatform.sa.dto.SaDtos;
import com.authplatform.sa.service.SaService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sa")
public class SaController {
  private final SaService service;

  public SaController(SaService service) {
    this.service = service;
  }

  @GetMapping("/me")
  SaDtos.AccountView me(@AuthenticationPrincipal AuthenticatedPrincipal principal) {
    return service.currentAccount(principal.subjectId());
  }

  @GetMapping("/analytics/overview")
  SaDtos.AnalyticsOverview analytics(
      @AuthenticationPrincipal AuthenticatedPrincipal principal, HttpServletRequest request) {
    return service.analytics(principal.subjectId(), request.getRemoteAddr());
  }

  @GetMapping("/accounts")
  SaDtos.PageResponse<SaDtos.AccountView> accounts(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.accounts(page, size, principal.subjectId(), request.getRemoteAddr());
  }

  @PostMapping("/accounts")
  SaDtos.AccountView createAccount(
      @Valid @RequestBody SaDtos.CreateSaRequest body,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.createSa(body, principal.subjectId(), request.getRemoteAddr());
  }

  @GetMapping("/accounts/{id}")
  SaDtos.AccountDetails account(
      @PathVariable UUID id,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.account(id, principal.subjectId(), request.getRemoteAddr());
  }

  @PatchMapping("/accounts/{id}")
  SaDtos.AccountView updateAccount(
      @PathVariable UUID id,
      @Valid @RequestBody SaDtos.UpdateAccountRequest body,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.updateAccount(id, body, principal.subjectId(), request.getRemoteAddr());
  }

  @GetMapping("/apps")
  SaDtos.PageResponse<SaDtos.AppView> apps(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @RequestParam(defaultValue = "") String q,
      @RequestParam(defaultValue = "") String sort,
      @RequestParam(defaultValue = "asc") String direction,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.apps(
        page, size, q, sort, direction, principal.subjectId(), request.getRemoteAddr());
  }

  @GetMapping("/apps/{id}")
  SaDtos.AppView app(
      @PathVariable UUID id,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.app(id, principal.subjectId(), request.getRemoteAddr());
  }

  @PatchMapping("/apps/{id}")
  SaDtos.AppView updateApp(
      @PathVariable UUID id,
      @Valid @RequestBody SaDtos.UpdateAppRequest body,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.updateApp(id, body, principal.subjectId(), request.getRemoteAddr());
  }

  @PostMapping("/apps/{id}/credentials/rotate")
  SaDtos.RotatedSecretResponse rotateSecret(
      @PathVariable UUID id,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.rotateSecret(id, principal.subjectId(), request.getRemoteAddr());
  }

  @GetMapping("/users")
  SaDtos.PageResponse<SaDtos.AppUserView> users(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @RequestParam(defaultValue = "") String q,
      @RequestParam(defaultValue = "") String status,
      @RequestParam(defaultValue = "") String sort,
      @RequestParam(defaultValue = "asc") String direction,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.users(
        page, size, q, status, sort, direction, principal.subjectId(), request.getRemoteAddr());
  }

  @GetMapping("/apps/{appId}/users")
  SaDtos.PageResponse<SaDtos.AppUserView> appUsers(
      @PathVariable UUID appId,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @RequestParam(defaultValue = "") String q,
      @RequestParam(defaultValue = "") String status,
      @RequestParam(defaultValue = "") String sort,
      @RequestParam(defaultValue = "asc") String direction,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.appUsers(
        appId,
        page,
        size,
        q,
        status,
        sort,
        direction,
        principal.subjectId(),
        request.getRemoteAddr());
  }

  @PatchMapping("/apps/{appId}/users/{userId}")
  SaDtos.AppUserView updateUser(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @Valid @RequestBody SaDtos.UpdateAppUserRequest body,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.updateUser(appId, userId, body, principal.subjectId(), request.getRemoteAddr());
  }

  @DeleteMapping("/apps/{appId}/users/{userId}")
  org.springframework.http.ResponseEntity<Void> deleteUser(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    service.deleteUser(appId, userId, principal.subjectId(), request.getRemoteAddr());
    return org.springframework.http.ResponseEntity.noContent().build();
  }

  @GetMapping("/audit-logs")
  SaDtos.PageResponse<SaDtos.AuditLogView> auditLogs(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int size,
      @RequestParam(defaultValue = "") String q,
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      HttpServletRequest request) {
    return service.auditLogs(page, size, q, principal.subjectId(), request.getRemoteAddr());
  }
}
