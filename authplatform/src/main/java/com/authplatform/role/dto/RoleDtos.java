package com.authplatform.role.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;

public final class RoleDtos {
  private RoleDtos() {}

  public record RoleView(
      UUID id,
      String name,
      String displayName,
      String description,
      boolean defaultRole,
      boolean enabled,
      List<String> permissions,
      long userCount) {}

  public record PermissionView(
      UUID id, UUID roleId, String key, String description, boolean enabled) {}

  public record RolePermissionUserView(
      UUID id, String name, String email, String status, boolean permissionEnabled) {}

  public record CreateRoleRequest(
      @NotBlank @Pattern(regexp = "[a-zA-Z0-9._:-]+") @Size(max = 60) String name,
      @Size(max = 120) String displayName,
      @Size(max = 255) String description,
      Boolean defaultRole,
      @Size(max = 50) List<@Valid CreatePermissionRequest> permissions) {}

  public record UpdateRoleRequest(
      @Pattern(regexp = "[a-zA-Z0-9._:-]+") @Size(max = 60) String name,
      @Size(max = 120) String displayName,
      @Size(max = 255) String description,
      Boolean enabled,
      Boolean defaultRole) {}

  public record CreatePermissionRequest(
      @NotBlank @Pattern(regexp = "[a-zA-Z0-9._:-]+") @Size(max = 100) String key,
      @Size(max = 255) String description) {}

  public record CreateRolePermissionRequest(
      @NotNull UUID roleId,
      @NotBlank @Pattern(regexp = "[a-zA-Z0-9._:-]+") @Size(max = 100) String key,
      @Size(max = 255) String description) {}

  public record UpdatePermissionRequest(
      @Pattern(regexp = "[a-zA-Z0-9._:-]+") @Size(max = 100) String key,
      @Size(max = 255) String description) {}

  public record AssignPermissionRequest(@NotNull UUID permissionId) {}

  public record AssignPermissionsRequest(
      @Size(max = 100) List<@NotNull UUID> permissionIds,
      @Size(max = 50) List<@Valid CreatePermissionRequest> newPermissions) {}

  public record SetRolePermissionsRequest(
      @NotNull @Size(max = 100) List<@NotNull UUID> permissionIds, @NotNull Boolean enabled) {}

  public record SetPermissionStatesRequest(
      @NotNull @Size(max = 100) List<@NotNull UUID> enablePermissionIds,
      @NotNull @Size(max = 100) List<@NotNull UUID> disablePermissionIds) {}

  public record SetUserPermissionsRequest(
      @NotNull @Size(max = 100) List<@NotNull UUID> permissionIds, @NotNull Boolean granted) {}

  public record SetUserPermissionRequest(@NotNull Boolean granted) {}

  public record UserRolePermissionsView(UUID roleId, List<String> permissionKeys) {}

  public record UserRolesView(UUID userId, List<RoleView> roles) {}
}
