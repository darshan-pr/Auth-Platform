"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";
import Link from "next/link";
import type { Permission, Role, RolePermissionUser, UserRolePermissions } from "../lib/types";
import { consoleApi } from "../lib/api";
import { Button, Card, ConfirmModal, Toggle } from "./ui";
import { Icon } from "./icon";
import managerStyles from "./roles-permissions-manager.module.css";

type RolesPermissionsManagerProps = {
  appId: string;
  applicationName: string;
  mode: "app" | "user";
  roles: Role[];
  permissions: Permission[];
  onRoles?: (roles: Role[]) => void;
  onPermissions?: (permissions: Permission[]) => void;
  userId?: string;
  userRolePermissions?: UserRolePermissions[];
  assignedRoleIds?: string[];
  onUpdated?: () => Promise<void>;
};

type PermissionDraft = { key: string; description: string };
type PermissionFilter = "all" | "enabled" | "disabled" | "users";

const DEFAULT_CRUD_PERMISSIONS: PermissionDraft[] = [
  { key: "create", description: "Create resources" },
  { key: "read", description: "View resources" },
  { key: "update", description: "Update resources" },
  { key: "delete", description: "Delete resources" },
];

const CRUD_PERMISSION_KEYS = DEFAULT_CRUD_PERMISSIONS.map(({ key }) => key);

function roleCrudPermissions(roleName: string): PermissionDraft[] {
  const prefix = roleName.trim() || "role";
  return DEFAULT_CRUD_PERMISSIONS.map((permission) => ({
    ...permission,
    key: `${prefix}.${permission.key}`,
  }));
}

function roleIsEnabled(role: Role) {
  return role.defaultRole || role.enabled;
}

export function RolesPermissionsManager({
  appId,
  applicationName,
  mode,
  roles,
  permissions,
  onRoles,
  onPermissions,
  userId,
  userRolePermissions,
  assignedRoleIds = [],
  onUpdated,
}: RolesPermissionsManagerProps) {
  const [selectedRoleId, setSelectedRoleId] = useState("");
  const [roleQuery, setRoleQuery] = useState("");
  const [permissionQuery, setPermissionQuery] = useState("");
  const [permissionUserQuery, setPermissionUserQuery] = useState("");
  const [permissionFilter, setPermissionFilter] = useState<PermissionFilter>("all");
  const [usersPermissionId, setUsersPermissionId] = useState("");
  const [permissionUsers, setPermissionUsers] = useState<RolePermissionUser[]>([]);
  const [loadingPermissionUsers, setLoadingPermissionUsers] = useState(false);
  const [selectedRolePermissions, setSelectedRolePermissions] = useState<{
    roleId: string;
    permissions: Permission[];
  } | null>(null);
  const [permissionLoadFailedForRoleId, setPermissionLoadFailedForRoleId] = useState("");
  const [editingAccess, setEditingAccess] = useState(false);
  const [permissionDraft, setPermissionDraft] = useState<Set<string>>(new Set());
  const [createRoleOpen, setCreateRoleOpen] = useState(false);
  const [assignPermissionsOpen, setAssignPermissionsOpen] = useState(false);
  const [editingPermission, setEditingPermission] = useState<Permission | null>(null);
  const [deletingPermission, setDeletingPermission] = useState<Permission | null>(null);
  const [assignedIds, setAssignedIds] = useState<Set<string>>(() => new Set(assignedRoleIds));
  const [showDescriptions, setShowDescriptions] = useState(true);
  const [pending, setPending] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const enabledRoles = useMemo(
    () => mode === "user" ? roles.filter(roleIsEnabled) : roles,
    [mode, roles],
  );
  const visibleRoles = useMemo(
    () => enabledRoles.filter((role) => `${role.name} ${role.displayName ?? ""} ${role.description ?? ""}`.toLowerCase().includes(roleQuery.toLowerCase())),
    [enabledRoles, roleQuery],
  );
  const selectedRole = enabledRoles.find((role) => role.id === selectedRoleId) ?? null;
  const assignedRoleSet = useMemo(() => new Set(assignedRoleIds), [assignedRoleIds]);
  const permissionKeysByRole = useMemo(
    () => new Map((userRolePermissions ?? []).map(({ roleId, permissionKeys }) => [roleId, new Set(permissionKeys)])),
    [userRolePermissions],
  );
  const userHasRole = selectedRole ? assignedIds.has(selectedRole.id) || selectedRole.defaultRole : false;
  const rolePermissions =
    selectedRole && selectedRolePermissions?.roleId === selectedRole.id
      ? selectedRolePermissions.permissions
      : [];
  const selectedPermissionForUsers =
    rolePermissions.find((permission) => permission.id === usersPermissionId) ??
    rolePermissions[0] ??
    null;
  const loadingSelectedRolePermissions =
    Boolean(selectedRole) &&
    selectedRolePermissions?.roleId !== selectedRole?.id &&
    permissionLoadFailedForRoleId !== selectedRole?.id;
  const isPermissionEnabled = (permission: Permission) => {
    if (!selectedRole || !permission.enabled) return false;
    if (mode === "app") return true;
    if (userRolePermissions) return permissionKeysByRole.get(selectedRole.id)?.has(permission.key) ?? false;
    return userHasRole;
  };
  const activePermissionCount = (role: Role) =>
    permissions.filter((permission) => permission.roleId === role.id && permission.enabled).length;
  const permissionIsChecked = (permission: Permission) =>
    editingAccess ? permissionDraft.has(permission.id) : isPermissionEnabled(permission);
  const enabledPermissionCount = rolePermissions.filter(isPermissionEnabled).length;
  const filteredPermissions = rolePermissions.filter((permission) => {
    const matchesQuery = `${permission.key} ${permission.description ?? ""}`.toLowerCase().includes(permissionQuery.toLowerCase());
    const enabled = isPermissionEnabled(permission);
    const matchesFilter =
      permissionFilter === "all" ||
      (permissionFilter === "enabled" && enabled) ||
      (permissionFilter === "disabled" && !enabled);
    return matchesQuery && matchesFilter;
  });
  const filteredPermissionUsers = permissionUsers.filter((user) =>
    `${user.name} ${user.email} ${user.status}`.toLowerCase().includes(permissionUserQuery.toLowerCase()),
  );
  const busy = Boolean(pending);

  useEffect(() => {
    setAssignedIds((current) => {
      const next = new Set(assignedRoleIds);
      if (current.size === next.size && [...current].every((id) => next.has(id))) return current;
      return next;
    });
  }, [assignedRoleIds]);

  useEffect(() => {
    if (visibleRoles.some((role) => role.id === selectedRoleId)) return;
    const initialRole = mode === "user"
      ? visibleRoles.find((role) => assignedRoleSet.has(role.id)) ?? visibleRoles[0]
      : visibleRoles[0];
    setSelectedRoleId(initialRole?.id ?? "");
  }, [mode, selectedRoleId, visibleRoles, assignedRoleSet]);

  useEffect(() => {
    if (!selectedRoleId) {
      setSelectedRolePermissions(null);
      setPermissionLoadFailedForRoleId("");
      return;
    }

    let active = true;
    setSelectedRolePermissions(null);
    setPermissionLoadFailedForRoleId("");
    setError("");
    setSuccess("");

    consoleApi
      .rolePermissions(appId, selectedRoleId)
      .then((nextPermissions) => {
        if (active) {
          setSelectedRolePermissions({ roleId: selectedRoleId, permissions: nextPermissions });
        }
      })
      .catch((err) => {
        if (active) {
          setPermissionLoadFailedForRoleId(selectedRoleId);
          setError(err instanceof Error ? err.message : "Unable to load role permissions");
          setSuccess("");
        }
      });

    return () => {
      active = false;
    };
  }, [appId, selectedRoleId]);

  useEffect(() => {
    setEditingAccess(false);
    setPermissionDraft(new Set());
  }, [selectedRoleId]);

  const showError = (message: string) => {
    setError(message);
    setSuccess("");
  };

  const showSuccess = (message: string) => {
    setSuccess(message);
    setError("");
  };

  useEffect(() => {
    if (
      mode !== "app" ||
      permissionFilter !== "users" ||
      !selectedRoleId ||
      !selectedPermissionForUsers
    ) {
      setPermissionUsers([]);
      setLoadingPermissionUsers(false);
      return;
    }

    let active = true;
    setPermissionUsers([]);
    setLoadingPermissionUsers(true);
    setError("");
    setSuccess("");

    consoleApi
      .rolePermissionUsers(appId, selectedRoleId, selectedPermissionForUsers.id)
      .then((users) => {
        if (active) setPermissionUsers(users);
      })
      .catch((err) => {
        if (active) {
          setError(err instanceof Error ? err.message : "Unable to load users for this permission");
          setSuccess("");
        }
      })
      .finally(() => {
        if (active) setLoadingPermissionUsers(false);
      });

    return () => {
      active = false;
    };
  }, [
    appId,
    mode,
    permissionFilter,
    selectedPermissionForUsers?.id,
    selectedRoleId,
  ]);

  const refreshRoleData = async () => {
    const roleId = selectedRoleId;
    const [nextRoles, nextPermissions] = await Promise.all([
      consoleApi.roles(appId),
      consoleApi.permissions(appId),
    ]);
    onRoles?.(nextRoles);
    onPermissions?.(nextPermissions);
    if (roleId) {
      setSelectedRolePermissions({
        roleId,
        permissions: nextPermissions.filter((permission) => permission.roleId === roleId),
      });
    }
  };

  const toggleRole = async (role: Role, enabled: boolean) => {
    setPending(`role:${role.id}`);
    setError("");
    try {
      if (mode === "app") {
        const updatedRole = await consoleApi.updateRole(appId, role.id, { enabled });
        onRoles?.(roles.map((current) => current.id === role.id ? updatedRole : current));
      } else {
        if (!userId) return;
        const previous = new Set(assignedIds);
        const next = new Set(previous);
        if (enabled) next.add(role.id);
        else next.delete(role.id);
        setAssignedIds(next);
        try {
          if (enabled) await consoleApi.assignRole(appId, userId, role.id);
          else await consoleApi.removeRole(appId, userId, role.id);
          await onUpdated?.();
        } catch (err) {
          setAssignedIds(previous);
          throw err;
        }
      }
      showSuccess(mode === "user" ? `Role ${enabled ? "assigned to" : "removed from"} this user` : `Role ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      showError(err instanceof Error ? err.message : "Unable to update role");
    } finally {
      setPending("");
    }
  };

  const createRole = async (draft: { name: string; displayName: string; description: string; defaultRole: boolean; permissions: PermissionDraft[] }) => {
    setPending("create-role");
    setError("");
    try {
      const role = await consoleApi.createRole(appId, {
        name: draft.name,
        displayName: draft.displayName || undefined,
        description: draft.description || undefined,
        defaultRole: draft.defaultRole,
        permissions: draft.permissions,
      });
      onRoles?.([...roles, role]);
      setSelectedRoleId(role.id);
      setCreateRoleOpen(false);

      if (mode === "user" && userId) {
        try {
          await consoleApi.assignRole(appId, userId, role.id);
          setAssignedIds((current) => new Set(current).add(role.id));
          await onUpdated?.();
          showSuccess(`Role "${role.name}" was created and assigned to this user`);
        } catch (err) {
          showError(`Role "${role.name}" was created, but could not be assigned: ${err instanceof Error ? err.message : "Unable to assign role"}`);
        }
      } else {
        showSuccess(`Role "${role.name}" created`);
      }
      try {
        await refreshRoleData();
      } catch (err) {
        showError(`Role was created, but the latest role data could not be loaded: ${err instanceof Error ? err.message : "Refresh failed"}`);
      }
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : "Unable to create role");
    } finally {
      setPending("");
    }
  };

  const assignPermissions = async (newPermissions: PermissionDraft[]) => {
    if (!selectedRole) return;
    setPending("assign-permissions");
    setError("");
    try {
      await consoleApi.assignPermissions(appId, selectedRole.id, { permissionIds: [], newPermissions });
      setAssignPermissionsOpen(false);
      try {
        await refreshRoleData();
        await onUpdated?.();
        showSuccess(`${newPermissions.length} permission${newPermissions.length === 1 ? "" : "s"} assigned to "${selectedRole.name}"`);
      } catch (err) {
        showError(`Permissions were assigned, but the latest data could not be loaded: ${err instanceof Error ? err.message : "Refresh failed"}`);
      }
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : "Unable to assign permissions");
    } finally {
      setPending("");
    }
  };

  const beginPermissionEdit = () => {
    setPermissionDraft(new Set(rolePermissions.filter(isPermissionEnabled).map((permission) => permission.id)));
    setEditingAccess(true);
    setError("");
  };

  const cancelPermissionEdit = () => {
    setEditingAccess(false);
    setPermissionDraft(new Set());
  };

  const enablePermissionIds = rolePermissions
    .filter((permission) => permissionDraft.has(permission.id) && !isPermissionEnabled(permission))
    .map((permission) => permission.id);
  const disablePermissionIds = rolePermissions
    .filter((permission) => !permissionDraft.has(permission.id) && isPermissionEnabled(permission))
    .map((permission) => permission.id);
  const permissionChangeCount = enablePermissionIds.length + disablePermissionIds.length;

  const savePermissionChanges = async () => {
    if (!selectedRole || !permissionChangeCount) return;
    if (mode === "user" && (!userId || !userHasRole)) {
      showError("Assign this role to the user before changing its permissions.");
      return;
    }
    setPending("save-permissions");
    setError("");
    try {
      if (mode === "app") {
        await consoleApi.setRolePermissionStates(appId, selectedRole.id, { enablePermissionIds, disablePermissionIds });
        await refreshRoleData();
      } else {
        if (!userId) throw new Error("A user must be selected before changing permissions.");
        await consoleApi.setUserRolePermissionStates(appId, userId, selectedRole.id, { enablePermissionIds, disablePermissionIds });
        await onUpdated?.();
      }
      setEditingAccess(false);
      setPermissionDraft(new Set());
      showSuccess(`${permissionChangeCount} permission change${permissionChangeCount === 1 ? "" : "s"} saved`);
    } catch (err) {
      showError(err instanceof Error ? err.message : "Unable to save permission changes");
    } finally {
      setPending("");
    }
  };

  const updatePermission = async (permission: Permission, draft: PermissionDraft) => {
    setPending(`update-permission:${permission.id}`);
    setError("");
    try {
      await consoleApi.updatePermission(appId, permission.id, draft);
      setEditingPermission(null);
      await refreshRoleData();
      showSuccess(`Permission "${draft.key}" updated`);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unable to update permission";
      showError(message);
      throw new Error(message);
    } finally {
      setPending("");
    }
  };

  const deletePermission = async () => {
    if (!deletingPermission || !selectedRole) return;
    const permission = deletingPermission;
    setPending(`delete-permission:${permission.id}`);
    setError("");
    try {
      await consoleApi.removePermission(appId, selectedRole.id, permission.id);
      setDeletingPermission(null);
      await refreshRoleData();
      showSuccess(`Permission "${permission.key}" deleted from "${selectedRole.name}"`);
    } catch (err) {
      showError(err instanceof Error ? err.message : "Unable to delete permission");
      setDeletingPermission(null);
    } finally {
      setPending("");
    }
  };

  const togglePermissionForUser = async (
    user: RolePermissionUser,
    granted: boolean,
  ) => {
    if (!selectedRole || !selectedPermissionForUsers) return;
    setPending(`user-permission:${user.id}`);
    setError("");
    try {
      await consoleApi.setUserRolePermission(
        appId,
        user.id,
        selectedRole.id,
        selectedPermissionForUsers.id,
        granted,
      );
      setPermissionUsers((current) =>
        current.map((item) =>
          item.id === user.id ? { ...item, permissionEnabled: granted } : item,
        ),
      );
      showSuccess(
        `${selectedPermissionForUsers.key} ${granted ? "enabled" : "disabled"} for ${user.name}`,
      );
    } catch (err) {
      showError(err instanceof Error ? err.message : "Unable to update user permission");
    } finally {
      setPending("");
    }
  };

  return <Card className={managerStyles.manager}>
    {(error || success) && <div aria-live="polite" className={`roles-manager-flash ${error ? "roles-manager-error" : "roles-manager-success"}`} role={error ? "alert" : "status"}>
      <Icon name={error ? "warning" : "check"} size={16} />
      <span>{error || success}</span>
      <button aria-label="Dismiss message" onClick={() => { setError(""); setSuccess(""); }} type="button"><Icon name="close" size={14} /></button>
    </div>}
    <div className="roles-manager-grid">
      <section aria-label="Application roles" className="roles-manager-role-panel">
        <div className="roles-manager-panel-heading">
          <div><h2>Application roles <span>{enabledRoles.length}</span></h2></div>
          {mode === "app" && <button aria-label="Create application role" className="roles-manager-add-role" disabled={busy || editingAccess} onClick={() => setCreateRoleOpen(true)} title="Create application role" type="button"><Icon name="plus" size={16} /></button>}
        </div>
        <p className="roles-manager-role-info">Select a role to view and manage its permissions.</p>
        <label className="roles-manager-search">
          <Icon name="search" size={15} />
          <input aria-label="Filter roles" disabled={editingAccess} onChange={(event) => setRoleQuery(event.target.value)} placeholder="Filter roles..." value={roleQuery} />
        </label>
        <div className="roles-manager-role-list">
          {visibleRoles.length ? visibleRoles.map((role) => {
            const active = role.id === selectedRoleId;
            const granted = assignedIds.has(role.id) || role.defaultRole;
            return <article className={`roles-manager-role-card${active ? " roles-manager-role-card-active" : ""}`} key={role.id}>
              <button aria-current={active ? "true" : undefined} className="roles-manager-role-select" disabled={editingAccess} onClick={() => setSelectedRoleId(role.id)} type="button">
                <span className="roles-manager-role-name">{role.displayName || role.name}{role.defaultRole && <span className="role-default-badge">Default</span>}</span>
                <code>{role.name}</code>
                {role.description && <span className="roles-manager-role-description">{role.description}</span>}
                <span className="roles-manager-role-meta"><span>{activePermissionCount(role)} active permission{activePermissionCount(role) === 1 ? "" : "s"}</span><span>{role.userCount} user{role.userCount === 1 ? "" : "s"}</span></span>
              </button>
              <div className="roles-manager-role-toggle">
                <Toggle
                  checked={mode === "user" ? granted : roleIsEnabled(role)}
                  disabled={busy || editingAccess || role.defaultRole || (mode === "user" && !userId)}
                  label={mode === "user" ? `${granted ? "Remove" : "Assign"} ${role.name} role` : `${roleIsEnabled(role) ? "Disable" : "Enable"} ${role.name} role`}
                  loading={pending === `role:${role.id}`}
                  onChange={(enabled) => toggleRole(role, enabled)}
                />
              </div>
            </article>;
          }) : <p className="roles-manager-empty">{roleQuery ? "No roles match this filter." : mode === "user" ? "No enabled application roles." : "No application roles yet."}</p>}
        </div>
      </section>

      <section
        aria-label="Permissions"
        className={`roles-manager-permission-panel ${managerStyles.permissionTransition}${loadingSelectedRolePermissions ? ` ${managerStyles.permissionTransitionLoading}` : ""}`}
      >
        <div className="roles-manager-panel-heading roles-manager-permission-heading">
          <div><h2>{selectedRole ? `Permissions for ${selectedRole.displayName || selectedRole.name}` : "Permissions"}</h2><p>{mode === "user" ? "Role permissions available to this user. Changes to access are user-specific." : "Manage the permissions enabled for this role."}</p></div>
          {mode === "app" && <Button disabled={!selectedRole || busy || editingAccess || loadingSelectedRolePermissions} icon="plus" onClick={() => setAssignPermissionsOpen(true)} title="Add permissions to this role" variant="quiet">Add permissions</Button>}
        </div>
        {selectedRole ? <>
          <div className="roles-manager-permission-toolbar">
            <label className="roles-manager-search roles-manager-permission-search">
              <Icon name="search" size={15} />
              <input
                aria-label={permissionFilter === "users" ? "Filter users" : "Filter permissions"}
                onChange={(event) =>
                  permissionFilter === "users"
                    ? setPermissionUserQuery(event.target.value)
                    : setPermissionQuery(event.target.value)
                }
                placeholder={permissionFilter === "users" ? "Filter users by name or email..." : "Filter permissions (e.g. read:*, user, audit)..."}
                value={permissionFilter === "users" ? permissionUserQuery : permissionQuery}
              />
            </label>
            <button aria-pressed={showDescriptions} aria-label={`${showDescriptions ? "Hide" : "Show"} permission descriptions`} className={`roles-manager-settings${showDescriptions ? " roles-manager-settings-active" : ""}`} onClick={() => setShowDescriptions((current) => !current)} title={`${showDescriptions ? "Hide" : "Show"} descriptions`} type="button"><Icon name="settings" size={16} /></button>
          </div>
          <div className="roles-manager-filter-toolbar">
            <div aria-label="Permission filters" className="roles-manager-filter-tabs" role="tablist">
              {([
                ["all", `All (${rolePermissions.length})`],
                ["enabled", `Enabled (${enabledPermissionCount})`],
                ["disabled", `Disabled (${rolePermissions.length - enabledPermissionCount})`],
              ] as const).map(([filter, label]) => <button aria-selected={permissionFilter === filter} className={permissionFilter === filter ? "roles-manager-filter-active" : ""} key={filter} onClick={() => setPermissionFilter(filter)} role="tab" type="button">{label}</button>)}
              {mode === "app" && <button aria-selected={permissionFilter === "users"} className={permissionFilter === "users" ? "roles-manager-filter-active" : ""} onClick={() => setPermissionFilter("users")} role="tab" type="button">Users</button>}
            </div>
            <div className="roles-manager-filter-actions">
              {permissionFilter !== "users" && rolePermissions.length > 0 && <Button aria-pressed={editingAccess} disabled={!selectedRole || busy || loadingSelectedRolePermissions || (mode === "user" && !userHasRole)} icon="edit" onClick={editingAccess ? cancelPermissionEdit : beginPermissionEdit} variant={editingAccess ? "secondary" : "quiet"}>{editingAccess ? "Cancel edit" : "Edit"}</Button>}
            </div>
          </div>
          {permissionFilter === "users" ? <div aria-busy={loadingPermissionUsers || loadingSelectedRolePermissions} className="roles-manager-users-panel">
            {loadingSelectedRolePermissions ? <p className="roles-manager-empty" role="status">Loading permissions for this role…</p> : selectedPermissionForUsers ? <>
              <label className="roles-manager-users-permission-select">
                <span>Permission</span>
                <select onChange={(event) => setUsersPermissionId(event.target.value)} value={selectedPermissionForUsers.id}>
                  {rolePermissions.map((permission) => <option key={permission.id} value={permission.id}>{permission.key}</option>)}
                </select>
              </label>
              <p className="roles-manager-users-hint">
                Users assigned to {selectedRole.name}. Toggle access to <code>{selectedPermissionForUsers.key}</code> for each user.
                {!selectedPermissionForUsers.enabled && " This permission is disabled for the role; enable it in the All tab before granting user access."}
              </p>
              {loadingPermissionUsers ? <p className="roles-manager-empty" role="status">Loading users…</p> : filteredPermissionUsers.length ? <div className="roles-manager-user-permission-list">
                {filteredPermissionUsers.map((user) => <div className="roles-manager-user-permission-row" key={user.id}>
                  <Link className="roles-manager-user-link" href={`/console/apps/${appId}/users/${user.id}`}>
                    <strong>{user.name}</strong>
                    <small>{user.email} · {user.status}</small>
                  </Link>
                  <span className="roles-manager-permission-enabled">{user.permissionEnabled ? "Enabled" : "Disabled"}</span>
                  <Toggle
                    checked={user.permissionEnabled}
                    disabled={busy || !selectedPermissionForUsers.enabled || !roleIsEnabled(selectedRole)}
                    label={`${user.permissionEnabled ? "Disable" : "Enable"} ${selectedPermissionForUsers.key} for ${user.name}`}
                    loading={pending === `user-permission:${user.id}`}
                    onChange={(enabled) => togglePermissionForUser(user, enabled)}
                  />
                </div>)}
              </div> : <p className="roles-manager-empty">{permissionUserQuery ? "No assigned users match this filter." : "No users are assigned to this role."}</p>}
              <p className="roles-manager-footer-note">User permission changes are saved automatically.</p>
            </> : <p className="roles-manager-empty">This role has no permissions to manage users for.</p>}
          </div> : <>
          {mode === "user" && !userHasRole && <p className="roles-manager-hint">Assign this role to the user before changing their permissions.</p>}
          <div aria-busy={loadingSelectedRolePermissions} className="roles-manager-permission-list">
            {loadingSelectedRolePermissions ? <div className={managerStyles.permissionLoading}>
              <p className="roles-manager-empty" role="status">Loading permissions for this role…</p>
              <div aria-hidden="true" className={managerStyles.permissionSkeleton}>
                <span className={managerStyles.permissionSkeletonRow} />
                <span className={managerStyles.permissionSkeletonRow} />
                <span className={managerStyles.permissionSkeletonRow} />
              </div>
            </div> : permissionLoadFailedForRoleId === selectedRole?.id
              ? <p className="roles-manager-empty" role="alert">Could not load permissions for this role.</p>
              : filteredPermissions.length ? filteredPermissions.map((permission) => {
              const isEnabled = permissionIsChecked(permission);
              return <div className={`roles-manager-permission-row ${managerStyles.permissionResult}`} key={permission.id}>
                <label className="roles-manager-permission-checkbox">
                  <input aria-label={`${isEnabled ? "Disable" : "Enable"} ${permission.key}`} checked={isEnabled} disabled={busy || !editingAccess || (mode === "user" && (!userHasRole || !permission.enabled))} onChange={(event) => setPermissionDraft((current) => {
                    const next = new Set(current);
                    if (event.target.checked) next.add(permission.id);
                    else next.delete(permission.id);
                    return next;
                  })} type="checkbox" />
                </label>
                <div className="roles-manager-permission-copy">
                  <code>{permission.key}</code>
                  {showDescriptions && permission.description && <small>{permission.description}</small>}
                </div>
                <span className="roles-manager-permission-enabled">{isEnabled ? "Enabled" : "Disabled"}</span>
                {mode === "app" && <div className="roles-manager-permission-actions">
                  <button aria-label={`Edit ${permission.key}`} disabled={busy || editingAccess} onClick={() => setEditingPermission(permission)} title="Edit permission" type="button"><Icon name="edit" size={14} /></button>
                  <button aria-label={`Delete ${permission.key}`} disabled={busy || editingAccess} onClick={() => setDeletingPermission(permission)} title="Delete permission" type="button"><Icon name="trash" size={14} /></button>
                </div>}
              </div>;
            }) : <p className="roles-manager-empty">{rolePermissions.length ? "No permissions match these filters." : "No permissions are available for this role."}</p>}
          </div>
          {editingAccess
            ? <div className="roles-manager-save-bar">
                <span>{permissionChangeCount ? `${permissionChangeCount} permission change${permissionChangeCount === 1 ? "" : "s"} ready to save` : "Select permissions to enable or disable."}</span>
                <Button disabled={busy || !permissionChangeCount} onClick={savePermissionChanges} variant="primary">{pending === "save-permissions" ? "Saving…" : "Save changes"}</Button>
              </div>
            : <p className="roles-manager-footer-note">All role permission changes persist automatically.</p>}
          </>}
        </> : <p className="roles-manager-empty">Select a role to manage its permissions.</p>}
      </section>
    </div>

    {createRoleOpen && <CreateRoleModal
      busy={pending === "create-role"}
      existingPermissions={permissions}
      mode={mode}
      roles={roles}
      onCancel={() => setCreateRoleOpen(false)}
      onCreate={createRole}
    />}
    {assignPermissionsOpen && selectedRole && <AssignPermissionsModal
      applicationName={applicationName}
      appName={selectedRole.name}
      busy={pending === "assign-permissions"}
      existingPermissions={rolePermissions}
      mode={mode}
      onCancel={() => setAssignPermissionsOpen(false)}
      onAssign={assignPermissions}
    />}
    {editingPermission && <EditPermissionModal
      busy={pending === `update-permission:${editingPermission.id}`}
      permission={editingPermission}
      onCancel={() => setEditingPermission(null)}
      onSave={(draft) => updatePermission(editingPermission, draft)}
    />}
    {deletingPermission && <ConfirmModal
      busy={pending === `delete-permission:${deletingPermission.id}`}
      confirmLabel="Delete permission"
      description={`This deletes the permission from "${selectedRole?.displayName || selectedRole?.name}" and removes its user-specific overrides.`}
      onCancel={() => setDeletingPermission(null)}
      onConfirm={deletePermission}
      resourceName={deletingPermission.key}
      title="Delete this permission?"
    />}
  </Card>;
}

function NewPermissionsComposer({
  existingPermissions,
  permissionName,
  staged,
  onChange,
}: {
  existingPermissions: Permission[];
  permissionName: string;
  staged: PermissionDraft[];
  onChange: (permissions: PermissionDraft[]) => void;
}) {
  const [key, setKey] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const permissionPrefix = `${permissionName.trim() || "role"}.`;

  const addPermission = () => {
    const suffix = key.trim();
    if (!suffix) { setError("Permission identifier is required."); return; }
    const nextKey = `${permissionPrefix}${suffix}`;
    if (nextKey.length > 100 || !/^[a-zA-Z0-9._:-]+$/.test(nextKey)) {
      setError("Use letters, numbers, periods, underscores, colons, or hyphens (100 characters max).");
      return;
    }
    if (existingPermissions.some((permission) => permission.key.toLowerCase() === nextKey.toLowerCase()) ||
      staged.some((permission) => permission.key.toLowerCase() === nextKey.toLowerCase())) {
      setError("This permission identifier already exists or is staged.");
      return;
    }
    onChange([...staged, { key: nextKey, description: description.trim() }]);
    setKey("");
    setDescription("");
    setError("");
  };

  return <div className="roles-manager-permission-composer">
    <div className="roles-manager-composer-heading"><strong>New permission</strong><span>Define permission scope and summary</span></div>
    <div className="roles-manager-composer-form">
      <label className="field"><span className="field-label">Permission identifier <b>*</b></span><span className="roles-manager-permission-identifier"><span aria-hidden="true">{permissionPrefix}</span><input aria-label={`Permission identifier after ${permissionPrefix}`} aria-invalid={Boolean(error)} onChange={(event) => { setKey(event.target.value); setError(""); }} placeholder="e.g. read:settings" value={key} /></span></label>
      <label className="field"><span className="field-label">Description</span><input onChange={(event) => setDescription(event.target.value)} placeholder="Brief description of this scope..." value={description} /></label>
      <Button aria-label="Add permission to staged list" disabled={!key.trim()} icon="plus" onClick={addPermission} type="button" variant="primary" />
    </div>
    {error && <p className="field-error" role="alert">{error}</p>}
    <div className="roles-manager-staged-heading"><strong>Permissions to add <span>{staged.length} staged</span></strong><span>Review scopes ready to be assigned</span></div>
    {staged.length ? <ul className="roles-manager-staged-list">{staged.map((permission) => <li key={permission.key}>
      <div><code>{permission.key}</code>{permission.description && <small>{permission.description}</small>}</div>
      <button aria-label={`Remove ${permission.key}`} onClick={() => onChange(staged.filter((item) => item.key !== permission.key))} type="button"><Icon name="trash" size={15} /></button>
    </li>)}</ul> : <p className="roles-manager-staged-empty">Permissions you add will appear here.</p>}
  </div>;
}

function CreateRoleModal({
  mode,
  roles,
  existingPermissions,
  busy,
  onCancel,
  onCreate,
}: {
  mode: "app" | "user";
  roles: Role[];
  existingPermissions: Permission[];
  busy: boolean;
  onCancel: () => void;
  onCreate: (draft: { name: string; displayName: string; description: string; defaultRole: boolean; permissions: PermissionDraft[] }) => Promise<void>;
}) {
  const [tab, setTab] = useState<"details" | "permissions">("details");
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [defaultRole, setDefaultRole] = useState(false);
  const [staged, setStaged] = useState<PermissionDraft[]>(() => roleCrudPermissions(""));
  const changeRoleName = (nextName: string) => {
    const previousPrefix = (name.trim() || "role") + ".";
    const nextPrefix = (nextName.trim() || "role") + ".";
    setStaged((current) =>
      current.map((permission) => {
        const defaultKey = CRUD_PERMISSION_KEYS.find(
          (action) => permission.key === `${previousPrefix}${action}`,
        );
        if (defaultKey) return { ...permission, key: `${nextPrefix}${defaultKey}` };
        return permission.key.startsWith(previousPrefix)
          ? { ...permission, key: `${nextPrefix}${permission.key.slice(previousPrefix.length)}` }
          : permission;
      }),
    );
    setName(nextName);
  };
  const [error, setError] = useState("");
  const nameError = name.trim() && !/^[a-z0-9_-]+$/.test(name.trim())
    ? "Use lowercase letters, numbers, hyphens, and underscores only."
    : roles.some((role) => role.name.toLowerCase() === name.trim().toLowerCase())
      ? "A role with this identifier already exists."
      : "";

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!name.trim() || nameError) {
      setError(nameError || "Role identifier is required.");
      setTab("details");
      return;
    }
    setError("");
    try {
      await onCreate({
        name: name.trim(),
        displayName: displayName.trim(),
        description: description.trim(),
        defaultRole,
        permissions: staged,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to create role");
    }
  };

  return <div className="modal-backdrop roles-manager-modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onCancel(); }}>
    <section aria-modal="true" className="modal roles-manager-modal" role="dialog" aria-labelledby="create-role-title">
      <header className="modal-header">
        <div><h2 id="create-role-title">Create application role</h2><p>Define a new role and assign permissions to control user access within this application.</p></div>
        <button aria-label="Close create role" className="icon-button" disabled={busy} onClick={onCancel} type="button"><Icon name="close" /></button>
      </header>
      <nav aria-label="Create role sections" className="roles-manager-modal-tabs" role="tablist">
        <button aria-selected={tab === "details"} className={tab === "details" ? "roles-manager-modal-tab-active" : ""} onClick={() => setTab("details")} role="tab" type="button">Role details</button>
        <button aria-selected={tab === "permissions"} className={tab === "permissions" ? "roles-manager-modal-tab-active" : ""} onClick={() => setTab("permissions")} role="tab" type="button">Permissions <span>{staged.length} staged</span></button>
      </nav>
      <form className="roles-manager-modal-body" onSubmit={submit}>
        {tab === "details" ? <div className="roles-manager-role-form">
          <label className="field"><span className="field-label">Role identifier / name <b>*</b></span><input aria-invalid={Boolean(nameError)} autoFocus maxLength={60} onChange={(event) => { changeRoleName(event.target.value); setError(""); }} placeholder="support_tier_2" value={name} /><span className="field-hint">Unique identifier for API checks. Default CRUD permissions use this name as their prefix.</span>{(nameError || error) && <span className="field-error">{nameError || error}</span>}</label>
          <label className="field"><span className="field-label">Display title / label</span><input maxLength={120} onChange={(event) => setDisplayName(event.target.value)} placeholder="Tier 2 Support Agent" value={displayName} /><span className="field-hint">Human-readable name shown in role and user listings.</span></label>
          <label className="field"><span className="field-label">Description</span><textarea maxLength={255} onChange={(event) => setDescription(event.target.value)} placeholder="Describe this role's access and responsibilities." rows={3} value={description} /></label>
          <label className="roles-manager-default-option"><input checked={defaultRole} onChange={(event) => setDefaultRole(event.target.checked)} type="checkbox" /><span><strong>Set as default role</strong><small>Automatically assign this role to newly provisioned users in this application.</small></span></label>
        </div> : <>
          <p className={managerStyles.crudPermissionHint}>Create, read, update, and delete permissions are included by default. Remove any you do not want before creating the role.</p>
          <NewPermissionsComposer existingPermissions={existingPermissions} onChange={setStaged} permissionName={name} staged={staged} />
        </>}
        {error && tab === "permissions" && <p className="field-error" role="alert">{error}</p>}
        <footer className="roles-manager-modal-footer">
          <span>{mode === "user" ? "The new role will also be assigned to this user." : "Permissions can be modified after creation."}</span>
          <div><Button disabled={busy} onClick={onCancel} type="button" variant="quiet">Cancel</Button><Button disabled={busy || !name.trim() || Boolean(nameError)} icon="plus" type="submit">{busy ? "Creating…" : mode === "user" ? `Create and assign${staged.length ? ` with ${staged.length} permissions` : " role"}` : `Create role${staged.length ? ` with ${staged.length} permissions` : ""}`}</Button></div>
        </footer>
      </form>
    </section>
  </div>;
}

function AssignPermissionsModal({
  applicationName,
  appName,
  mode,
  existingPermissions,
  busy,
  onCancel,
  onAssign,
}: {
  applicationName: string;
  appName: string;
  mode: "app" | "user";
  existingPermissions: Permission[];
  busy: boolean;
  onCancel: () => void;
  onAssign: (permissions: PermissionDraft[]) => Promise<void>;
}) {
  const [staged, setStaged] = useState<PermissionDraft[]>([]);
  const [error, setError] = useState("");
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!staged.length) { setError("Add at least one permission."); return; }
    setError("");
    try {
      await onAssign(staged);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to assign permissions");
    }
  };

  return <div className="modal-backdrop roles-manager-modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onCancel(); }}>
    <section aria-modal="true" aria-labelledby="assign-permissions-title" className="modal roles-manager-modal roles-manager-assign-modal" role="dialog">
      <header className="modal-header">
        <div><h2 id="assign-permissions-title">Assign permissions to Role: <code>{appName}</code></h2><p>Application: {applicationName}{mode === "user" ? " · New permissions are added to the application role and become available to all users assigned to it." : ""}</p></div>
        <button aria-label="Close assign permissions" className="icon-button" disabled={busy} onClick={onCancel} type="button"><Icon name="close" /></button>
      </header>
      <form className="roles-manager-modal-body" onSubmit={submit}>
        <NewPermissionsComposer existingPermissions={existingPermissions} onChange={setStaged} permissionName={appName} staged={staged} />
        {error && <p className="field-error" role="alert">{error}</p>}
        <footer className="roles-manager-modal-footer">
          <span>{staged.length} permission{staged.length === 1 ? "" : "s"} ready to assign to role "{appName}".</span>
          <div><Button disabled={busy} onClick={onCancel} type="button" variant="quiet">Cancel</Button><Button disabled={busy || staged.length === 0} icon="plus" type="submit">{busy ? "Assigning…" : `Assign ${staged.length} permission${staged.length === 1 ? "" : "s"}`}</Button></div>
        </footer>
      </form>
    </section>
  </div>;
}

function EditPermissionModal({
  permission,
  busy,
  onCancel,
  onSave,
}: {
  permission: Permission;
  busy: boolean;
  onCancel: () => void;
  onSave: (draft: PermissionDraft) => Promise<void>;
}) {
  const [key, setKey] = useState(permission.key);
  const [description, setDescription] = useState(permission.description ?? "");
  const [error, setError] = useState("");
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedKey = key.trim();
    if (!trimmedKey || trimmedKey.length > 100 || !/^[a-zA-Z0-9._:-]+$/.test(trimmedKey)) {
      setError("Use letters, numbers, periods, underscores, colons, or hyphens (100 characters max).");
      return;
    }
    setError("");
    try {
      await onSave({ key: trimmedKey, description: description.trim() });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update permission");
    }
  };

  return <div className="modal-backdrop roles-manager-modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onCancel(); }}>
    <section aria-modal="true" aria-labelledby="edit-permission-title" className="modal roles-manager-modal roles-manager-edit-modal" role="dialog">
      <header className="modal-header"><div><h2 id="edit-permission-title">Edit permission</h2><p>Update this application permission identifier and description.</p></div><button aria-label="Close edit permission" className="icon-button" disabled={busy} onClick={onCancel} type="button"><Icon name="close" /></button></header>
      <form className="roles-manager-modal-body" onSubmit={submit}>
        <label className="field"><span className="field-label">Permission identifier <b>*</b></span><input autoFocus onChange={(event) => { setKey(event.target.value); setError(""); }} value={key} /></label>
        <label className="field"><span className="field-label">Description</span><textarea maxLength={255} onChange={(event) => setDescription(event.target.value)} rows={3} value={description} /></label>
        {error && <p className="field-error" role="alert">{error}</p>}
        <footer className="roles-manager-modal-footer"><span>Changes update permissions assigned to this application.</span><div><Button disabled={busy} onClick={onCancel} type="button" variant="quiet">Cancel</Button><Button disabled={busy} type="submit">{busy ? "Saving…" : "Save changes"}</Button></div></footer>
      </form>
    </section>
  </div>;
}
