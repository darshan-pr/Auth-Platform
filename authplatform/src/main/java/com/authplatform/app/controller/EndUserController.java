package com.authplatform.app.controller;

import com.authplatform.app.dto.AppDtos;
import com.authplatform.app.service.EndUserService;
import com.authplatform.common.dto.PageResult;
import com.authplatform.common.security.AuthenticatedPrincipal;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/console/apps/{appId}/end-users")
public class EndUserController {
  private final EndUserService service;

  public EndUserController(EndUserService service) {
    this.service = service;
  }

  @GetMapping
  PageResult<AppDtos.AppUserView> list(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @PathVariable UUID appId,
      @RequestParam(defaultValue = "") String q,
      @RequestParam(defaultValue = "") String status,
      @RequestParam(defaultValue = "") String sort,
      @RequestParam(defaultValue = "asc") String direction,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size) {
    return service.list(principal.subjectId(), appId, q, status, sort, direction, page, size);
  }

  @PostMapping("/invitations")
  AppDtos.InviteUsersResponse invite(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @PathVariable UUID appId,
      @Valid @RequestBody AppDtos.InviteUsersRequest request) {
    return service.invite(principal.subjectId(), appId, request);
  }

  @PostMapping("/{userId}/invitation")
  AppDtos.AppUserView resend(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @PathVariable UUID appId,
      @PathVariable UUID userId) {
    return service.resendInvitation(principal.subjectId(), appId, userId);
  }
}
