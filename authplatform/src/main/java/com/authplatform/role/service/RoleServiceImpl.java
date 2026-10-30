package com.authplatform.role.service;

import com.authplatform.auth.service.SessionService;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.role.dto.RoleDtos;
import com.authplatform.role.entity.Role;
import com.authplatform.role.repository.RoleRepository;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RoleServiceImpl implements RoleService {
  private static final List<RoleDtos.CreatePermissionRequest> DEFAULT_CRUD_PERMISSIONS =
      List.of(
          new RoleDtos.CreatePermissionRequest("create", "Create resources"),
          new RoleDtos.CreatePermissionRequest("read", "View resources"),
          new RoleDtos.CreatePermissionRequest("update", "Update resources"),
          new RoleDtos.CreatePermissionRequest("delete", "Delete resources"));
  private static final RowMapper<RoleDtos.PermissionView> PERMISSION_VIEW_MAPPER =
      (rs, n) ->
          new RoleDtos.PermissionView(
              (UUID) rs.getObject("id"),
              (UUID) rs.getObject("role_id"),
              rs.getString("key"),
              rs.getString("description"),
              rs.getBoolean("enabled"));

  private final RoleRepository roles;
  private final JdbcTemplate jdbc;
  private final SessionService sessions;

  public RoleServiceImpl(RoleRepository roles, JdbcTemplate jdbc, SessionService sessions) {
    this.roles = roles;
    this.jdbc = jdbc;
    this.sessions = sessions;
  }

  @Transactional
  public Role createDefaultRole(UUID appId) {
    return roles.save(Role.defaultFor(appId));
  }

  @Transactional
  public void assignDefaultRole(UUID appId, UUID userId) {
    roles
        .findByAppIdAndDefaultRoleTrue(appId)
        .ifPresent(
            role ->
                jdbc.update(
                    "insert into app_user_roles(app_user_id,role_id) values (?,?) on conflict do nothing",
                    userId,
                    role.getId()));
  }

  @Transactional(readOnly = true)
  public List<String> roleNames(UUID appId, UUID userId) {
    return jdbc.query(
        "select r.name from roles r join app_user_roles ur on ur.role_id=r.id where ur.app_user_id=? and r.app_id=? and r.enabled=true",
        (rs, n) -> rs.getString(1),
        userId,
        appId);
  }

  @Transactional(readOnly = true)
  public List<String> permissionKeys(UUID appId, UUID userId) {
    return userRolePermissions(appId, userId).stream()
        .flatMap(role -> role.permissionKeys().stream())
        .distinct()
        .sorted()
        .toList();
  }

  @Transactional(readOnly = true)
  public List<RoleDtos.UserRolePermissionsView> userRolePermissions(UUID appId, UUID userId) {
    requireUserExists(appId, userId);
    List<Role> appRoles =
        roles.findAllByAppId(appId).stream().filter(Role::isEnabled).toList();
    Map<UUID, Set<String>> permissionKeysByRole = new LinkedHashMap<>();
    appRoles.forEach(role -> permissionKeysByRole.put(role.getId(), new LinkedHashSet<>()));
    jdbc.query(
        """
        select r.id as role_id, p.key
        from roles r
        join permissions p on p.role_id = r.id and p.enabled = true
        left join app_user_role_permission_overrides uo
          on uo.app_user_id = ?
          and uo.role_id = r.id
          and uo.permission_id = p.id
        left join app_user_roles ur
          on ur.app_user_id = ?
          and ur.role_id = r.id
        where r.app_id = ?
          and r.enabled = true
          and ur.app_user_id is not null
          and uo.granted is distinct from false
        order by r.id, p.key
        """,
        (rs, rowNum) -> Map.entry((UUID) rs.getObject("role_id"), rs.getString("key")),
        userId,
        userId,
        appId)
        .forEach(
            permission -> {
              Set<String> keys = permissionKeysByRole.get(permission.getKey());
              if (keys != null) keys.add(permission.getValue());
            });
    return appRoles.stream()
        .map(
            role ->
                new RoleDtos.UserRolePermissionsView(
                    role.getId(),
                    List.copyOf(permissionKeysByRole.getOrDefault(role.getId(), Set.of()))))
        .toList();
  }

  @Transactional(readOnly = true)
  public com.authplatform.app.dto.AppDtos.RoleSummary findDefault(UUID appId) {
    return roles
        .findByAppIdAndDefaultRoleTrue(appId)
        .map(role -> new com.authplatform.app.dto.AppDtos.RoleSummary(role.getId(), role.getName()))
        .orElse(null);
  }

  @Transactional(readOnly = true)
  public List<RoleDtos.RoleView> listRoles(UUID appId) {
    return roles.findAllByAppId(appId).stream().map(role -> roleView(role)).toList();
  }

  @Transactional
  public RoleDtos.RoleView createRole(UUID appId, RoleDtos.CreateRoleRequest request) {
    String name = request.name().trim();
    if (roles.findAllByAppId(appId).stream()
        .anyMatch(role -> role.getName().equalsIgnoreCase(name)))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "Role name already exists");

    if (Boolean.TRUE.equals(request.defaultRole()))
      roles.findByAppIdAndDefaultRoleTrue(appId).ifPresent(role -> role.setDefaultRole(false));

    Role role =
        Role.create(
            appId,
            name,
            blankToNull(request.displayName()),
            blankToNull(request.description()));
    role.setDefaultRole(Boolean.TRUE.equals(request.defaultRole()));
    try {
      role = roles.saveAndFlush(role);
    } catch (org.springframework.dao.DataIntegrityViolationException ex) {
      throw new ApiException(ErrorCode.ROLE_NAME_TAKEN);
    }

    List<RoleDtos.CreatePermissionRequest> initialPermissions =
        request.permissions() == null ? defaultCrudPermissions(name) : request.permissions();
    for (RoleDtos.CreatePermissionRequest permissionRequest : initialPermissions) {
      createPermissionRecord(appId, role.getId(), permissionRequest);
    }
    return roleView(role);
  }

  private List<RoleDtos.CreatePermissionRequest> defaultCrudPermissions(String roleName) {
    return DEFAULT_CRUD_PERMISSIONS.stream()
        .map(
            permission ->
                new RoleDtos.CreatePermissionRequest(
                    roleName + "." + permission.key(), permission.description()))
        .toList();
  }

  @Transactional
  public RoleDtos.RoleView updateRole(UUID appId, UUID roleId, RoleDtos.UpdateRoleRequest request) {
    Role role = findRole(appId, roleId);
    if (role.isDefaultRole() && Boolean.FALSE.equals(request.enabled()))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "The default role cannot be disabled");
    if (role.isDefaultRole() && Boolean.FALSE.equals(request.defaultRole()))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "The application must have a default role");
    boolean wasEnabled = role.isEnabled();
    if (request.name() != null
        && roles.findAllByAppId(appId).stream()
            .anyMatch(
                value ->
                    !value.getId().equals(roleId)
                        && value.getName().equalsIgnoreCase(request.name().trim())))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "Role name already exists");
    if (Boolean.TRUE.equals(request.defaultRole()) && !role.isDefaultRole())
      roles.findByAppIdAndDefaultRoleTrue(appId).ifPresent(value -> value.setDefaultRole(false));
    role.update(
        request.name() == null ? null : request.name().trim(),
        request.displayName() == null ? null : blankToNull(request.displayName()),
        request.description() == null ? null : blankToNull(request.description()),
        request.enabled());
    if (Boolean.TRUE.equals(request.defaultRole())) role.setDefaultRole(true);
    if (wasEnabled && !role.isEnabled()) revokeRoleUsers(roleId);
    return roleView(role);
  }

  @Transactional
  public void deleteRole(UUID appId, UUID roleId) {
    Role role = findRole(appId, roleId);
    if (role.isDefaultRole())
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "The default role cannot be deleted");
    revokeRoleUsers(roleId);
    roles.delete(role);
  }

  @Transactional(readOnly = true)
  public List<RoleDtos.PermissionView> listPermissions(UUID appId) {
    return jdbc.query(
        "select id, role_id, key, description, enabled from permissions where app_id=? and role_id is not null order by role_id, key",
        PERMISSION_VIEW_MAPPER,
        appId);
  }

  @Transactional(readOnly = true)
  public List<RoleDtos.PermissionView> listRolePermissions(UUID appId, UUID roleId) {
    findRole(appId, roleId);
    return jdbc.query(
        "select id, role_id, key, description, enabled from permissions where app_id=? and role_id=? order by key",
        PERMISSION_VIEW_MAPPER,
        appId,
        roleId);
  }

  @Transactional(readOnly = true)
  public List<RoleDtos.RolePermissionUserView> usersWithRolePermission(
      UUID appId, UUID roleId, UUID permissionId) {
    findRole(appId, roleId);
    requirePermissionForRole(appId, roleId, permissionId);
    return jdbc.query(
        """
        select u.id, u.name, u.email, u.status,
               (p.enabled and coalesce(uo.granted, true)) as permission_enabled
        from app_user_roles ur
        join app_users u on u.id = ur.app_user_id and u.app_id = ?
        join permissions p on p.role_id = ur.role_id
        left join app_user_role_permission_overrides uo
          on uo.app_user_id = u.id
          and uo.role_id = ur.role_id
          and uo.permission_id = p.id
        where ur.role_id = ?
          and p.id = ?
        order by lower(u.name), lower(u.email)
        """,
        (rs, rowNum) ->
            new RoleDtos.RolePermissionUserView(
                (UUID) rs.getObject("id"),
                rs.getString("name"),
                rs.getString("email"),
                rs.getString("status"),
                rs.getBoolean("permission_enabled")),
        appId,
        roleId,
        permissionId);
  }

  @Transactional
  public RoleDtos.PermissionView createPermission(
      UUID appId, UUID roleId, RoleDtos.CreatePermissionRequest request) {
    findRole(appId, roleId);
    return createPermissionRecord(appId, roleId, request);
  }

  private RoleDtos.PermissionView createPermissionRecord(
      UUID appId, UUID roleId, RoleDtos.CreatePermissionRequest request) {
    UUID id = UUID.randomUUID();
    String key = request.key().trim();
    try {
      jdbc.update(
          "insert into permissions(id, app_id, role_id, key, description, enabled) values (?,?,?,?,?,true)",
          id,
          appId,
          roleId,
          key,
          blankToNull(request.description()));
    } catch (org.springframework.dao.DataIntegrityViolationException ex) {
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED, "Permission key already exists for this role");
    }
    return new RoleDtos.PermissionView(
        id, roleId, key, blankToNull(request.description()), true);
  }

  @Transactional
  public void assignPermission(UUID appId, UUID roleId, UUID permissionId) {
    findRole(appId, roleId);
    assignPermissionToRole(appId, roleId, permissionId);
    revokeRoleUsers(roleId);
  }

  @Transactional
  public void assignPermissions(
      UUID appId, UUID roleId, RoleDtos.AssignPermissionsRequest request) {
    findRole(appId, roleId);
    Set<UUID> permissionIds =
    new LinkedHashSet<>(
        request.permissionIds() == null ? List.of() : request.permissionIds());
    List<RoleDtos.CreatePermissionRequest> newPermissions =
    request.newPermissions() == null ? List.of() : request.newPermissions();
    if (permissionIds.isEmpty() && newPermissions.isEmpty())
      throw new ApiException(
      ErrorCode.VALIDATION_FAILED, "Select or create at least one permission");

    permissionIds.forEach(permissionId -> assignPermissionToRole(appId, roleId, permissionId));
    for (RoleDtos.CreatePermissionRequest permissionRequest : newPermissions)
      createPermissionRecord(appId, roleId, permissionRequest);
    revokeRoleUsers(roleId);
  }

  @Transactional
  public void setRolePermissions(
      UUID appId, UUID roleId, RoleDtos.SetRolePermissionsRequest request) {
    findRole(appId, roleId);
    Set<UUID> permissionIds = new LinkedHashSet<>(request.permissionIds());
    permissionIds.forEach(permissionId -> requirePermissionForRole(appId, roleId, permissionId));
    for (UUID permissionId : permissionIds) {
      jdbc.update(
          "update permissions set enabled=? where id=? and app_id=? and role_id=?",
          request.enabled(),
          permissionId,
          appId,
          roleId);
    }
    if (!permissionIds.isEmpty()) revokeRoleUsers(roleId);
  }

  @Transactional
  public void setRolePermissionStates(
      UUID appId, UUID roleId, RoleDtos.SetPermissionStatesRequest request) {
    findRole(appId, roleId);
    Set<UUID> enabledIds = new LinkedHashSet<>(request.enablePermissionIds());
    Set<UUID> disabledIds = new LinkedHashSet<>(request.disablePermissionIds());
    if (enabledIds.stream().anyMatch(disabledIds::contains))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "A permission cannot be enabled and disabled together");
    Set<UUID> changedIds = new LinkedHashSet<>(enabledIds);
    changedIds.addAll(disabledIds);
    changedIds.forEach(permissionId -> requirePermissionForRole(appId, roleId, permissionId));
    enabledIds.forEach(
        permissionId ->
            jdbc.update(
                "update permissions set enabled=true where id=? and app_id=? and role_id=?",
                permissionId,
                appId,
                roleId));
    disabledIds.forEach(
        permissionId ->
            jdbc.update(
                "update permissions set enabled=false where id=? and app_id=? and role_id=?",
                permissionId,
                appId,
                roleId));
    if (!changedIds.isEmpty()) revokeRoleUsers(roleId);
  }

  @Transactional
  public RoleDtos.PermissionView updatePermission(
      UUID appId, UUID permissionId, RoleDtos.UpdatePermissionRequest request) {
    List<RoleDtos.PermissionView> matches =
    jdbc.query(
        "select id, role_id, key, description, enabled from permissions where id=? and app_id=?",
        (rs, n) ->
            new RoleDtos.PermissionView(
                (UUID) rs.getObject("id"),
                (UUID) rs.getObject("role_id"),
                rs.getString("key"),
                rs.getString("description"),
                rs.getBoolean("enabled")),
        permissionId,
        appId);
    if (matches.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);

    RoleDtos.PermissionView current = matches.getFirst();
    String nextKey = request.key() == null ? current.key() : request.key().trim();
    String nextDescription =
    request.description() == null ? current.description() : blankToNull(request.description());
    try {
      jdbc.update(
      "update permissions set key=?, description=? where id=? and app_id=?",
      nextKey,
      nextDescription,
      permissionId,
      appId);
    } catch (org.springframework.dao.DataIntegrityViolationException ex) {
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED, "Permission key already exists for this role");
    }
    if (!Objects.equals(current.key(), nextKey)) revokePermissionUsers(permissionId);
    return new RoleDtos.PermissionView(
        permissionId, current.roleId(), nextKey, nextDescription, current.enabled());
  }

  @Transactional
  public void deletePermission(UUID appId, UUID permissionId) {
    requirePermissionExists(appId, permissionId);
    revokePermissionUsers(permissionId);
    jdbc.update("delete from permissions where id=? and app_id=?", permissionId, appId);
  }

  @Transactional
  public void removePermission(UUID appId, UUID roleId, UUID permissionId) {
    findRole(appId, roleId);
    requirePermissionForRole(appId, roleId, permissionId);
    revokeRoleUsers(roleId);
    jdbc.update(
        "delete from permissions where id=? and app_id=? and role_id=?",
        permissionId,
        appId,
        roleId);
  }

  @Transactional(readOnly = true)
  public RoleDtos.UserRolesView userRoles(UUID appId, UUID userId) {
    requireUserExists(appId, userId);
    List<UUID> ids =
        jdbc.query(
            "select role_id from app_user_roles ur join roles r on r.id=ur.role_id where ur.app_user_id=? and r.app_id=? and r.enabled=true",
            (rs, n) -> (UUID) rs.getObject(1),
            userId,
            appId);
    return new RoleDtos.UserRolesView(
        userId, ids.stream().map(id -> roleView(findRole(appId, id))).toList());
  }

  @Transactional
  public void assignRole(UUID appId, UUID userId, UUID roleId) {
    userRoles(appId, userId);
    Role role = findRole(appId, roleId);
    if (!role.isEnabled())
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "Disabled roles cannot be assigned");
    jdbc.update(
        "insert into app_user_roles(app_user_id, role_id) values (?,?) on conflict do nothing",
        userId,
        roleId);
    sessions.revokeAllForAppUser(userId);
  }

  @Transactional
  public void removeRole(UUID appId, UUID userId, UUID roleId) {
    userRoles(appId, userId);
    Role role = findRole(appId, roleId);
    if (role.isDefaultRole())
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "The default role cannot be removed");
    jdbc.update("delete from app_user_roles where app_user_id=? and role_id=?", userId, roleId);
    sessions.revokeAllForAppUser(userId);
  }

  @Transactional
  public void setUserPermission(
      UUID appId, UUID userId, UUID roleId, UUID permissionId, boolean granted) {
    setUserPermissions(
        appId,
        userId,
        roleId,
        new RoleDtos.SetUserPermissionsRequest(List.of(permissionId), granted));
  }

  @Transactional
  public void setUserPermissions(
      UUID appId,
      UUID userId,
      UUID roleId,
      RoleDtos.SetUserPermissionsRequest request) {
    requireUserExists(appId, userId);
    if (jdbc.queryForObject(
            "select count(*) from app_user_roles where app_user_id=? and role_id=?",
            Long.class,
            userId,
            roleId)
        == 0)
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED, "Assign the role to the user before changing its permissions");
    Role role = findRole(appId, roleId);
    if (!role.isEnabled()) throw new ApiException(ErrorCode.NOT_FOUND);
    Set<UUID> permissionIds = new LinkedHashSet<>(request.permissionIds());
    for (UUID permissionId : permissionIds) {
      if (jdbc.queryForObject(
              """
              select count(*)
              from permissions
              where role_id = ?
                and id = ?
                and app_id = ?
              """,
              Long.class,
              roleId,
              permissionId,
              appId)
          == 0) throw new ApiException(ErrorCode.NOT_FOUND);
      if (request.granted()
          && !Boolean.TRUE.equals(
              jdbc.queryForObject(
                  "select enabled from permissions where role_id=? and id=? and app_id=?",
                  Boolean.class,
                  roleId,
                  permissionId,
                  appId)))
        throw new ApiException(
            ErrorCode.VALIDATION_FAILED, "Enable the permission for the role before granting it");
      jdbc.update(
          """
          insert into app_user_role_permission_overrides(
            app_user_id, role_id, permission_id, granted
          )
          values (?, ?, ?, ?)
          on conflict (app_user_id, role_id, permission_id)
          do update set granted = excluded.granted, updated_at = now()
          """,
          userId,
          roleId,
          permissionId,
          request.granted());
    }
    if (!permissionIds.isEmpty()) sessions.revokeAllForAppUser(userId);
  }

  @Transactional
  public void setUserPermissionStates(
      UUID appId,
      UUID userId,
      UUID roleId,
      RoleDtos.SetPermissionStatesRequest request) {
    requireUserExists(appId, userId);
    if (jdbc.queryForObject(
            "select count(*) from app_user_roles where app_user_id=? and role_id=?",
            Long.class,
            userId,
            roleId)
        == 0)
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED, "Assign the role to the user before changing its permissions");
    Role role = findRole(appId, roleId);
    if (!role.isEnabled()) throw new ApiException(ErrorCode.NOT_FOUND);

    Set<UUID> enabledIds = new LinkedHashSet<>(request.enablePermissionIds());
    Set<UUID> disabledIds = new LinkedHashSet<>(request.disablePermissionIds());
    if (enabledIds.stream().anyMatch(disabledIds::contains))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "A permission cannot be enabled and disabled together");
    Set<UUID> changedIds = new LinkedHashSet<>(enabledIds);
    changedIds.addAll(disabledIds);
    for (UUID permissionId : changedIds) {
      if (jdbc.queryForObject(
              """
              select count(*)
              from permissions
              where role_id = ?
                and id = ?
                and app_id = ?
              """,
              Long.class,
              roleId,
              permissionId,
              appId)
          == 0) throw new ApiException(ErrorCode.NOT_FOUND);
      if (enabledIds.contains(permissionId)
          && !Boolean.TRUE.equals(
              jdbc.queryForObject(
                  "select enabled from permissions where role_id=? and id=? and app_id=?",
                  Boolean.class,
                  roleId,
                  permissionId,
                  appId)))
        throw new ApiException(
            ErrorCode.VALIDATION_FAILED, "Enable the permission for the role before granting it");
    }
    enabledIds.forEach(permissionId -> setUserPermissionOverride(userId, roleId, permissionId, true));
    disabledIds.forEach(permissionId -> setUserPermissionOverride(userId, roleId, permissionId, false));
    if (!changedIds.isEmpty()) sessions.revokeAllForAppUser(userId);
  }

  private void setUserPermissionOverride(
      UUID userId, UUID roleId, UUID permissionId, boolean granted) {
    jdbc.update(
        """
        insert into app_user_role_permission_overrides(
          app_user_id, role_id, permission_id, granted
        )
        values (?, ?, ?, ?)
        on conflict (app_user_id, role_id, permission_id)
        do update set granted = excluded.granted, updated_at = now()
        """,
        userId,
        roleId,
        permissionId,
        granted);
  }

  private void requireUserExists(UUID appId, UUID userId) {
    if (jdbc.queryForObject(
            "select count(*) from app_users where id=? and app_id=?", Long.class, userId, appId)
        == 0) throw new ApiException(ErrorCode.NOT_FOUND);
  }

  private Role findRole(UUID appId, UUID roleId) {
    return roles
        .findByIdAndAppId(roleId, appId)
        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
  }

  private RoleDtos.RoleView roleView(Role role) {
    List<String> permissions =
        jdbc.query(
            "select p.key from permissions p where p.role_id=? order by p.key",
            (rs, n) -> rs.getString(1),
            role.getId());
    return new RoleDtos.RoleView(
        role.getId(),
        role.getName(),
        role.getDisplayName(),
        role.getDescription(),
        role.isDefaultRole(),
        role.isEnabled(),
        permissions,
        jdbc.queryForObject(
            "select count(*) from app_user_roles where role_id=?", Long.class, role.getId()));
  }

  private void requirePermissionExists(UUID appId, UUID permissionId) {
    if (jdbc.queryForObject(
            "select count(*) from permissions where id=? and app_id=?",
            Long.class,
            permissionId,
            appId)
        == 0) throw new ApiException(ErrorCode.NOT_FOUND);
  }

  private void requirePermissionForRole(UUID appId, UUID roleId, UUID permissionId) {
    if (jdbc.queryForObject(
                "select count(*) from permissions where role_id=? and id=? and app_id=?",
                Long.class,
                roleId,
                permissionId,
                appId)
            == 0) throw new ApiException(ErrorCode.NOT_FOUND);
  }

  private void assignPermissionToRole(UUID appId, UUID roleId, UUID permissionId) {
    try {
      int updated =
              jdbc.update(
                  """
                  update permissions
                  set role_id=?, enabled=true
                  where id=? and app_id=? and (role_id=? or role_id is null)
                  """,
                  roleId,
                  permissionId,
                  appId,
                  roleId);
      if (updated == 0) throw new ApiException(ErrorCode.NOT_FOUND);
    } catch (org.springframework.dao.DataIntegrityViolationException ex) {
      throw new ApiException(
              ErrorCode.VALIDATION_FAILED, "Permission key already exists for this role");
    }
  }

  private void revokePermissionUsers(UUID permissionId) {
    jdbc.query(
                "select role_id from permissions where id=? and role_id is not null",
                (rs, n) -> (UUID) rs.getObject(1),
                permissionId)
            .forEach(this::revokeRoleUsers);
  }

  private String blankToNull(String value) {
    return value == null || value.isBlank() ? null : value.trim();
  }

  private void revokeRoleUsers(UUID roleId) {
    jdbc.query(
            "select app_user_id from app_user_roles where role_id=?",
            (rs, n) -> (UUID) rs.getObject(1),
            roleId)
        .forEach(sessions::revokeAllForAppUser);
  }
}
