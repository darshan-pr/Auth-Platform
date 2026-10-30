package com.authplatform.role.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authplatform.auth.service.SessionService;
import com.authplatform.common.exception.ApiException;
import com.authplatform.role.dto.RoleDtos;
import com.authplatform.role.entity.Role;
import com.authplatform.role.repository.RoleRepository;
import java.sql.ResultSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

class RoleServiceImplTest {
  @Test
  void createsRoleWithRoleQualifiedCrudDefaultsWhenPermissionsAreOmitted() {
    UUID appId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    Role savedRole = mock(Role.class);
    when(roles.findAllByAppId(appId)).thenReturn(List.of());
    when(roles.saveAndFlush(any(Role.class))).thenReturn(savedRole);
    when(savedRole.getId()).thenReturn(roleId);
    when(savedRole.getName()).thenReturn("developer");
    when(savedRole.isEnabled()).thenReturn(true);
    when(jdbc.query(
            contains("select p.key from permissions"),
            any(RowMapper.class),
            eq(roleId)))
        .thenReturn(List.of("developer.create", "developer.delete", "developer.read", "developer.update"));
    when(jdbc.queryForObject(
            contains("select count(*) from app_user_roles"), eq(Long.class), eq(roleId)))
        .thenReturn(0L);

    new RoleServiceImpl(roles, jdbc, sessions)
        .createRole(
            appId,
            new RoleDtos.CreateRoleRequest("developer", null, null, false, null));

    ArgumentCaptor<String> keys = ArgumentCaptor.forClass(String.class);
    verify(jdbc, times(4))
        .update(
            contains("insert into permissions"),
            any(UUID.class),
            eq(appId),
            eq(roleId),
            keys.capture(),
            any());
    assertThat(keys.getAllValues())
        .containsExactly("developer.create", "developer.read", "developer.update", "developer.delete");
  }

  @Test
  void listsOnlyPermissionsThatHaveARoleOwner() throws Exception {
    UUID appId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    when(jdbc.query(
            contains("role_id is not null"), any(RowMapper.class), eq(appId)))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              RowMapper<RoleDtos.PermissionView> mapper = invocation.getArgument(1);
              ResultSet resultSet = mock(ResultSet.class);
              when(resultSet.getObject("id")).thenReturn(permissionId);
              when(resultSet.getObject("role_id")).thenReturn(roleId);
              when(resultSet.getString("key")).thenReturn("users:read");
              when(resultSet.getString("description")).thenReturn("Read users");
              when(resultSet.getBoolean("enabled")).thenReturn(true);
              return List.of(mapper.mapRow(resultSet, 0));
            });

    List<RoleDtos.PermissionView> result =
        new RoleServiceImpl(roles, jdbc, sessions).listPermissions(appId);

    assertThat(result)
        .containsExactly(
            new RoleDtos.PermissionView(permissionId, roleId, "users:read", "Read users", true));
  }

  @Test
  void loadsPermissionsForTheSelectedRoleOnly() throws Exception {
    UUID appId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    when(roles.findByIdAndAppId(roleId, appId)).thenReturn(Optional.of(mock(Role.class)));
    when(jdbc.query(
            contains("where app_id=? and role_id=?"),
            any(RowMapper.class),
            eq(appId),
            eq(roleId)))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              RowMapper<RoleDtos.PermissionView> mapper = invocation.getArgument(1);
              ResultSet resultSet = mock(ResultSet.class);
              when(resultSet.getObject("id")).thenReturn(permissionId);
              when(resultSet.getObject("role_id")).thenReturn(roleId);
              when(resultSet.getString("key")).thenReturn("users:read");
              when(resultSet.getString("description")).thenReturn("Read users");
              when(resultSet.getBoolean("enabled")).thenReturn(true);
              return List.of(mapper.mapRow(resultSet, 0));
            });

    List<RoleDtos.PermissionView> result =
        new RoleServiceImpl(roles, jdbc, sessions).listRolePermissions(appId, roleId);

    assertThat(result)
        .containsExactly(
            new RoleDtos.PermissionView(permissionId, roleId, "users:read", "Read users", true));
  }

  @Test
  void returnsUsersAssignedToRoleWithEffectivePermissionState() throws Exception {
    UUID appId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    when(roles.findByIdAndAppId(roleId, appId)).thenReturn(Optional.of(mock(Role.class)));
    when(jdbc.queryForObject(
            contains("from permissions where role_id=?"), eq(Long.class), eq(roleId), eq(permissionId), eq(appId)))
        .thenReturn(1L);
    when(jdbc.query(
            contains("from app_user_roles ur"),
            any(RowMapper.class),
            eq(appId),
            eq(roleId),
            eq(permissionId)))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              RowMapper<RoleDtos.RolePermissionUserView> mapper = invocation.getArgument(1);
              ResultSet resultSet = mock(ResultSet.class);
              when(resultSet.getObject("id")).thenReturn(userId);
              when(resultSet.getString("name")).thenReturn("Darshan");
              when(resultSet.getString("email")).thenReturn("darshan@example.com");
              when(resultSet.getString("status")).thenReturn("ACTIVE");
              when(resultSet.getBoolean("permission_enabled")).thenReturn(false);
              return List.of(mapper.mapRow(resultSet, 0));
            });

    List<RoleDtos.RolePermissionUserView> result =
        new RoleServiceImpl(roles, jdbc, sessions)
            .usersWithRolePermission(appId, roleId, permissionId);

    assertThat(result)
        .containsExactly(
            new RoleDtos.RolePermissionUserView(
                userId, "Darshan", "darshan@example.com", "ACTIVE", false));
  }

  @Test
  void returnsPermissionsForEnabledRoles() throws Exception {
    UUID appId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    Role role = mock(Role.class);
    when(role.getId()).thenReturn(roleId);
    when(role.isEnabled()).thenReturn(true);
    when(roles.findAllByAppId(appId)).thenReturn(List.of(role));
    when(jdbc.queryForObject(
            "select count(*) from app_users where id=? and app_id=?", Long.class, userId, appId))
        .thenReturn(1L);
    when(jdbc.query(
            contains("from roles r"),
            any(RowMapper.class),
            eq(userId),
            eq(userId),
            eq(appId)))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              RowMapper<Map.Entry<UUID, String>> mapper = invocation.getArgument(1);
              ResultSet resultSet = mock(ResultSet.class);
              when(resultSet.getObject("role_id")).thenReturn(roleId);
              when(resultSet.getString("key")).thenReturn("users:read");
              return List.of(mapper.mapRow(resultSet, 0));
            });

    List<RoleDtos.UserRolePermissionsView> result =
        new RoleServiceImpl(roles, jdbc, sessions).userRolePermissions(appId, userId);

    assertThat(result)
        .containsExactly(new RoleDtos.UserRolePermissionsView(roleId, List.of("users:read")));
  }

  @Test
  void storesRoleScopedUserPermissionOverrideAndRevokesSessions() {
    UUID appId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    Role role = mock(Role.class);
    when(role.isEnabled()).thenReturn(true);
    when(roles.findByIdAndAppId(roleId, appId)).thenReturn(Optional.of(role));
    when(jdbc.queryForObject(
            "select count(*) from app_users where id=? and app_id=?",
            Long.class,
            userId,
            appId))
        .thenReturn(1L);
    when(jdbc.queryForObject(
            "select count(*) from app_user_roles where app_user_id=? and role_id=?",
            Long.class,
            userId,
            roleId))
        .thenReturn(1L);
    when(jdbc.queryForObject(
            contains("from permissions"),
            eq(Long.class),
            eq(roleId),
            eq(permissionId),
            eq(appId)))
        .thenReturn(1L);

    new RoleServiceImpl(roles, jdbc, sessions)
        .setUserPermission(appId, userId, roleId, permissionId, false);

    verify(jdbc)
        .update(
            contains("app_user_role_permission_overrides"),
            eq(userId),
            eq(roleId),
            eq(permissionId),
            eq(false));
    verify(sessions).revokeAllForAppUser(userId);
  }

  @Test
  void rejectsPermissionThatIsNotEnabledForTheRole() {
    UUID appId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    Role role = mock(Role.class);
    when(role.isEnabled()).thenReturn(true);
    when(roles.findByIdAndAppId(roleId, appId)).thenReturn(Optional.of(role));
    when(jdbc.queryForObject(
            "select count(*) from app_users where id=? and app_id=?",
            Long.class,
            userId,
            appId))
        .thenReturn(1L);
    when(jdbc.queryForObject(
            "select count(*) from app_user_roles where app_user_id=? and role_id=?",
            Long.class,
            userId,
            roleId))
        .thenReturn(1L);
    when(jdbc.queryForObject(
            contains("from permissions"),
            eq(Long.class),
            eq(roleId),
            eq(permissionId),
            eq(appId)))
        .thenReturn(0L);

    assertThatThrownBy(
            () ->
                new RoleServiceImpl(roles, jdbc, sessions)
                    .setUserPermission(appId, userId, roleId, permissionId, true))
        .isInstanceOf(ApiException.class);
    verify(jdbc, never())
        .update(
            contains("app_user_role_permission_overrides"),
            eq(userId),
            eq(roleId),
            eq(permissionId),
            eq(true));
    verify(sessions, never()).revokeAllForAppUser(userId);
  }

  @Test
  void rejectsGrantingPermissionDisabledForRole() {
    UUID appId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    Role role = mock(Role.class);
    when(role.isEnabled()).thenReturn(true);
    when(roles.findByIdAndAppId(roleId, appId)).thenReturn(Optional.of(role));
    when(jdbc.queryForObject(
            "select count(*) from app_users where id=? and app_id=?",
            Long.class,
            userId,
            appId))
        .thenReturn(1L);
    when(jdbc.queryForObject(
            "select count(*) from app_user_roles where app_user_id=? and role_id=?",
            Long.class,
            userId,
            roleId))
        .thenReturn(1L);
    when(jdbc.queryForObject(
            contains("from permissions"),
            eq(Long.class),
            eq(roleId),
            eq(permissionId),
            eq(appId)))
        .thenReturn(1L);
    when(jdbc.queryForObject(
            contains("select enabled"),
            eq(Boolean.class),
            eq(roleId),
            eq(permissionId),
            eq(appId)))
        .thenReturn(false);

    assertThatThrownBy(
            () ->
                new RoleServiceImpl(roles, jdbc, sessions)
                    .setUserPermission(appId, userId, roleId, permissionId, true))
        .isInstanceOf(ApiException.class);
    verify(jdbc, never())
        .update(
            contains("app_user_role_permission_overrides"),
            eq(userId),
            eq(roleId),
            eq(permissionId),
            eq(true));
    verify(sessions, never()).revokeAllForAppUser(userId);
  }

  @Test
  void createsPermissionOwnedBySelectedRole() {
    UUID appId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    when(roles.findByIdAndAppId(roleId, appId)).thenReturn(Optional.of(mock(Role.class)));

    RoleDtos.PermissionView permission =
        new RoleServiceImpl(roles, jdbc, sessions)
            .createPermission(
                appId,
                roleId,
                new RoleDtos.CreatePermissionRequest("users:upload", "Upload user data"));

    assertThat(permission.roleId()).isEqualTo(roleId);
    assertThat(permission.enabled()).isTrue();
    verify(jdbc)
        .update(
            contains("insert into permissions"),
            any(UUID.class),
            eq(appId),
            eq(roleId),
            eq("users:upload"),
            eq("Upload user data"));
  }

  @Test
  void rejectsPermissionOverridesForUnassignedRoles() {
    UUID appId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID permissionId = UUID.randomUUID();
    JdbcTemplate jdbc = mock(JdbcTemplate.class);
    RoleRepository roles = mock(RoleRepository.class);
    SessionService sessions = mock(SessionService.class);
    when(jdbc.queryForObject(
            "select count(*) from app_users where id=? and app_id=?",
            Long.class,
            userId,
            appId))
        .thenReturn(1L);
    when(jdbc.queryForObject(
            "select count(*) from app_user_roles where app_user_id=? and role_id=?",
            Long.class,
            userId,
            roleId))
        .thenReturn(0L);

    assertThatThrownBy(
            () ->
                new RoleServiceImpl(roles, jdbc, sessions)
                    .setUserPermission(appId, userId, roleId, permissionId, true))
        .isInstanceOf(ApiException.class);
    verify(jdbc, never())
        .update(
            contains("app_user_role_permission_overrides"),
            eq(userId),
            eq(roleId),
            eq(permissionId),
            eq(true));
    verify(sessions, never()).revokeAllForAppUser(userId);
  }
}
