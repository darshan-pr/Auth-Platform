package com.authplatform.app.controller;

import com.authplatform.app.dto.AppDtos;
import com.authplatform.app.service.AppService;
import com.authplatform.common.security.AuthenticatedPrincipal;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
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
@RequestMapping("/api/console/apps")
public class AppController {
  private final AppService service;

  public AppController(AppService service) {
    this.service = service;
  }

  @PostMapping
  ResponseEntity<AppDtos.AppCreatedResponse> create(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @Valid @RequestBody AppDtos.CreateAppRequest request) {
    var body = service.create(principal.subjectId(), request);
    return ResponseEntity.created(URI.create("/api/console/apps/" + body.id())).body(body);
  }

  @GetMapping
  List<AppDtos.AppResponse> list(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size) {
    return service.list(principal.subjectId(), page, size);
  }

  @GetMapping("/page")
  com.authplatform.common.dto.PageResult<AppDtos.AppResponse> search(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @RequestParam(defaultValue = "") String q,
      @RequestParam(defaultValue = "") String sort,
      @RequestParam(defaultValue = "asc") String direction,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size) {
    return service.search(principal.subjectId(), q, sort, direction, page, size);
  }

  @GetMapping("/{id}")
  AppDtos.AppResponse get(
      @AuthenticationPrincipal AuthenticatedPrincipal principal, @PathVariable UUID id) {
    return service.get(principal.subjectId(), id);
  }

  @PatchMapping("/{id}")
  AppDtos.AppResponse update(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @PathVariable UUID id,
      @Valid @RequestBody AppDtos.UpdateAppRequest request) {
    return service.update(principal.subjectId(), id, request);
  }

  @PostMapping("/{id}/credentials/rotate")
  AppDtos.RotatedSecretResponse rotate(
      @AuthenticationPrincipal AuthenticatedPrincipal principal, @PathVariable UUID id) {
    return service.rotate(principal.subjectId(), id);
  }

  @GetMapping("/{id}/users")
  List<AppDtos.AppUserView> users(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @PathVariable UUID id,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int size) {
    return service.listUsers(principal.subjectId(), id, page, size);
  }

  @PatchMapping("/{appId}/users/{userId}")
  AppDtos.AppUserView updateUser(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @Valid @RequestBody AppDtos.UpdateAppUserRequest request) {
    return service.updateUser(principal.subjectId(), appId, userId, request);
  }

  @DeleteMapping("/{appId}/users/{userId}")
  ResponseEntity<Void> deleteUser(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @PathVariable UUID appId,
      @PathVariable UUID userId) {
    service.deleteUser(principal.subjectId(), appId, userId);
    return ResponseEntity.noContent().build();
  }
}
