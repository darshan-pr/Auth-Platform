package com.authplatform.role.controller;

import com.authplatform.app.repository.AppRepository;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.common.security.AuthenticatedPrincipal;
import com.authplatform.role.dto.RoleDtos;
import com.authplatform.role.service.RoleService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/console/apps/{appId}", "/api/sa/apps/{appId}"})
public class RoleManagementController {
  private final RoleService roles;
  private final AppRepository apps;

  public RoleManagementController(RoleService roles, AppRepository apps) {
    this.roles = roles;
    this.apps = apps;
  }

  @GetMapping("/roles")
  List<RoleDtos.RoleView> roles(
      @PathVariable UUID appId, Authentication authentication, HttpServletRequest request) {
    authorize(appId, authentication, request);
    return roles.listRoles(appId);
  }

  @PostMapping("/roles")
  RoleDtos.RoleView createRole(
      @PathVariable UUID appId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.CreateRoleRequest body) {
    authorize(appId, authentication, request);
    return roles.createRole(appId, body);
  }

  @PatchMapping("/roles/{roleId}")
  RoleDtos.RoleView updateRole(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.UpdateRoleRequest body) {
    authorize(appId, authentication, request);
    return roles.updateRole(appId, roleId, body);
  }

  @DeleteMapping("/roles/{roleId}")
  ResponseEntity<Void> deleteRole(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request) {
    authorize(appId, authentication, request);
    roles.deleteRole(appId, roleId);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/permissions")
  List<RoleDtos.PermissionView> permissions(
      @PathVariable UUID appId, Authentication authentication, HttpServletRequest request) {
    authorize(appId, authentication, request);
    return roles.listPermissions(appId);
  }

  @GetMapping("/roles/{roleId}/permissions")
  List<RoleDtos.PermissionView> rolePermissions(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request) {
    authorize(appId, authentication, request);
    return roles.listRolePermissions(appId, roleId);
  }

  @GetMapping("/roles/{roleId}/permissions/{permissionId}/users")
  List<RoleDtos.RolePermissionUserView> usersWithRolePermission(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      @PathVariable UUID permissionId,
      Authentication authentication,
      HttpServletRequest request) {
    authorize(appId, authentication, request);
    return roles.usersWithRolePermission(appId, roleId, permissionId);
  }

  @PostMapping("/permissions")
  RoleDtos.PermissionView createPermission(
      @PathVariable UUID appId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.CreateRolePermissionRequest body) {
    authorize(appId, authentication, request);
    return roles.createPermission(
        appId,
        body.roleId(),
        new RoleDtos.CreatePermissionRequest(body.key(), body.description()));
  }

  @PostMapping("/roles/{roleId}/permissions")
  ResponseEntity<Void> assignPermission(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.AssignPermissionRequest body) {
    authorize(appId, authentication, request);
    roles.assignPermission(appId, roleId, body.permissionId());
    return ResponseEntity.noContent().build();
  }

  @DeleteMapping("/roles/{roleId}/permissions/{permissionId}")
  ResponseEntity<Void> removePermission(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      @PathVariable UUID permissionId,
      Authentication authentication,
      HttpServletRequest request) {
    authorize(appId, authentication, request);
    roles.removePermission(appId, roleId, permissionId);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/roles/{roleId}/permissions/batch")
  ResponseEntity<Void> assignPermissions(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.AssignPermissionsRequest body) {
    authorize(appId, authentication, request);
    roles.assignPermissions(appId, roleId, body);
    return ResponseEntity.noContent().build();
  }

  @PutMapping("/roles/{roleId}/permissions")
  ResponseEntity<Void> setRolePermissions(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.SetRolePermissionsRequest body) {
    authorize(appId, authentication, request);
    roles.setRolePermissions(appId, roleId, body);
    return ResponseEntity.noContent().build();
  }

  @PatchMapping("/roles/{roleId}/permissions")
  ResponseEntity<Void> setRolePermissionStates(
      @PathVariable UUID appId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.SetPermissionStatesRequest body) {
    authorize(appId, authentication, request);
    roles.setRolePermissionStates(appId, roleId, body);
    return ResponseEntity.noContent().build();
  }

  @PatchMapping("/permissions/{permissionId}")
  RoleDtos.PermissionView updatePermission(
      @PathVariable UUID appId,
      @PathVariable UUID permissionId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.UpdatePermissionRequest body) {
    authorize(appId, authentication, request);
    return roles.updatePermission(appId, permissionId, body);
  }

  @DeleteMapping("/permissions/{permissionId}")
  ResponseEntity<Void> deletePermission(
      @PathVariable UUID appId,
      @PathVariable UUID permissionId,
      Authentication authentication,
      HttpServletRequest request) {
    authorize(appId, authentication, request);
    roles.deletePermission(appId, permissionId);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/users/{userId}/roles")
  RoleDtos.UserRolesView userRoles(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      Authentication authentication,
      HttpServletRequest request) {
    authorize(appId, authentication, request);
    return roles.userRoles(appId, userId);
  }

  @PostMapping("/users/{userId}/roles/{roleId}")
  ResponseEntity<Void> assignRole(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request) {
    authorize(appId, authentication, request);
    roles.assignRole(appId, userId, roleId);
    return ResponseEntity.noContent().build();
  }

  @DeleteMapping("/users/{userId}/roles/{roleId}")
  ResponseEntity<Void> removeRole(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request) {
    authorize(appId, authentication, request);
    roles.removeRole(appId, userId, roleId);
    return ResponseEntity.noContent().build();
  }

  @PutMapping("/users/{userId}/roles/{roleId}/permissions/{permissionId}")
  ResponseEntity<Void> setUserPermission(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @PathVariable UUID roleId,
      @PathVariable UUID permissionId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.SetUserPermissionRequest body) {
    authorize(appId, authentication, request);
    roles.setUserPermission(appId, userId, roleId, permissionId, body.granted());
    return ResponseEntity.noContent().build();
  }

  @PutMapping("/users/{userId}/roles/{roleId}/permissions")
  ResponseEntity<Void> setUserPermissions(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.SetUserPermissionsRequest body) {
    authorize(appId, authentication, request);
    roles.setUserPermissions(appId, userId, roleId, body);
    return ResponseEntity.noContent().build();
  }

  @PatchMapping("/users/{userId}/roles/{roleId}/permissions")
  ResponseEntity<Void> setUserPermissionStates(
      @PathVariable UUID appId,
      @PathVariable UUID userId,
      @PathVariable UUID roleId,
      Authentication authentication,
      HttpServletRequest request,
      @Valid @RequestBody RoleDtos.SetPermissionStatesRequest body) {
    authorize(appId, authentication, request);
    roles.setUserPermissionStates(appId, userId, roleId, body);
    return ResponseEntity.noContent().build();
  }

  private void authorize(UUID appId, Authentication authentication, HttpServletRequest request) {
    boolean sa =
        authentication != null
            && authentication.getAuthorities().stream()
                .anyMatch(value -> "ROLE_SA".equals(value.getAuthority()));
    if (sa && request.getRequestURI().startsWith("/api/sa/")) {
      if (!apps.existsById(appId)) throw new ApiException(ErrorCode.NOT_FOUND);
      return;
    }
    Object principal = authentication == null ? null : authentication.getPrincipal();
    if (!(principal instanceof AuthenticatedPrincipal authenticated)
        || !apps.findByIdAndOwnerAccountId(appId, authenticated.subjectId()).isPresent())
      throw new ApiException(ErrorCode.ACCESS_DENIED);
  }
}
