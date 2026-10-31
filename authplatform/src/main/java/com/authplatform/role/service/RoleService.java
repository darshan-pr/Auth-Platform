package com.authplatform.role.service;

import com.authplatform.role.dto.RoleDtos;
import com.authplatform.role.entity.Role;
import java.util.List;
import java.util.UUID;

public interface RoleService {
  Role createDefaultRole(UUID appId);

  void assignDefaultRole(UUID appId, UUID userId);

  void assignDefaultRole(UUID appId, java.util.Collection<UUID> userIds);

  List<String> roleNames(UUID appId, UUID userId);

  List<String> permissionKeys(UUID appId, UUID userId);

  List<RoleDtos.UserRolePermissionsView> userRolePermissions(UUID appId, UUID userId);

  com.authplatform.app.dto.AppDtos.RoleSummary findDefault(UUID appId);

  List<RoleDtos.RoleView> listRoles(UUID appId);

  RoleDtos.RoleView createRole(UUID appId, RoleDtos.CreateRoleRequest request);

  RoleDtos.RoleView updateRole(UUID appId, UUID roleId, RoleDtos.UpdateRoleRequest request);

  void deleteRole(UUID appId, UUID roleId);

  List<RoleDtos.PermissionView> listPermissions(UUID appId);

  List<RoleDtos.PermissionView> listRolePermissions(UUID appId, UUID roleId);

  List<RoleDtos.RolePermissionUserView> usersWithRolePermission(
      UUID appId, UUID roleId, UUID permissionId);

  RoleDtos.PermissionView createPermission(
      UUID appId, UUID roleId, RoleDtos.CreatePermissionRequest request);

  void assignPermission(UUID appId, UUID roleId, UUID permissionId);

  void removePermission(UUID appId, UUID roleId, UUID permissionId);

  void assignPermissions(
      UUID appId, UUID roleId, RoleDtos.AssignPermissionsRequest request);

  void setRolePermissions(
      UUID appId, UUID roleId, RoleDtos.SetRolePermissionsRequest request);

  void setRolePermissionStates(
      UUID appId, UUID roleId, RoleDtos.SetPermissionStatesRequest request);

  RoleDtos.PermissionView updatePermission(
      UUID appId, UUID permissionId, RoleDtos.UpdatePermissionRequest request);

  void deletePermission(UUID appId, UUID permissionId);

  RoleDtos.UserRolesView userRoles(UUID appId, UUID userId);

  void assignRole(UUID appId, UUID userId, UUID roleId);

  void removeRole(UUID appId, UUID userId, UUID roleId);

  void setUserPermission(
      UUID appId, UUID userId, UUID roleId, UUID permissionId, boolean granted);

  void setUserPermissions(
      UUID appId, UUID userId, UUID roleId, RoleDtos.SetUserPermissionsRequest request);

  void setUserPermissionStates(
      UUID appId, UUID userId, UUID roleId, RoleDtos.SetPermissionStatesRequest request);
}
