"use client";

import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import type { AppUserDetails, ConsoleApp, Permission, Role, SessionInfo } from "../lib/types";
import { consoleApi } from "../lib/api";
import { Button, Card, ConfirmModal, CopyButton, ErrorBanner, Field, Loading, PageHeader, Pagination, Stack, StatusBadge } from "./ui";
import { Icon } from "./icon";
import { RolesPermissionsManager } from "./roles-permissions-manager";

const HISTORY_PAGE_SIZE = 20;

export function ConsoleAppUserPage() {
  const { id: appId, userId } = useParams<{ id: string; userId: string }>();
  const router = useRouter();
  const [app, setApp] = useState<ConsoleApp | null>(null);
  const [details, setDetails] = useState<AppUserDetails | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [editing, setEditing] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyFilter, setHistoryFilter] = useState("");
  const [historyPage, setHistoryPage] = useState(0);
  const [error, setError] = useState("");
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [sessionError, setSessionError] = useState("");
  const [pendingSession, setPendingSession] = useState("");
  const [revokeAllConfirm, setRevokeAllConfirm] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const loadRequest = useRef(0);

  const load = useCallback(async () => {
    const requestId = ++loadRequest.current;
    try {
      const [nextApp, nextDetails, nextRoles, nextPermissions] = await Promise.all([consoleApi.app(appId), consoleApi.appUserDetails(appId, userId), consoleApi.roles(appId), consoleApi.permissions(appId)]);
      if (requestId !== loadRequest.current) return;
      setError("");
      setApp(nextApp); setDetails(nextDetails); setRoles(nextRoles); setPermissions(nextPermissions);
      try {
        const nextSessions = await consoleApi.appUserSessions(appId, userId);
        if (requestId !== loadRequest.current) return;
        setSessions(nextSessions);
        setSessionError("");
      } catch (err) {
        if (requestId !== loadRequest.current) return;
        setSessionError(err instanceof Error ? err.message : "Unable to load user sessions");
      }
    } catch (err) {
      if (requestId !== loadRequest.current) return;
      setError(err instanceof Error ? err.message : "Unable to load user");
    }
  }, [appId, userId]);
  useEffect(() => {
    void load();
    return () => { loadRequest.current += 1; };
  }, [load]);
  useEffect(() => {
    setHistoryOpen(false);
    setHistoryFilter("");
    setHistoryPage(0);
  }, [appId, userId]);

  const revokeSession = async (sessionId: string) => {
    setPendingSession(sessionId);
    setSessionError("");
    try {
      await consoleApi.revokeAppUserSession(appId, userId, sessionId);
      setSessions((current) => current.filter((session) => session.id !== sessionId));
    } catch (err) {
      setSessionError(err instanceof Error ? err.message : "Unable to revoke session");
    } finally {
      setPendingSession("");
    }
  };

  const revokeAllSessions = async () => {
    setPendingSession("all");
    try {
      await consoleApi.revokeAllAppUserSessions(appId, userId);
      setSessions([]);
      setSessionError("");
    } catch (err) {
      setSessionError(err instanceof Error ? err.message : "Unable to revoke sessions");
    } finally {
      setPendingSession("");
      setRevokeAllConfirm(false);
    }
  };

  const deleteUser = async () => {
    setDeleting(true);
    try {
      await consoleApi.deleteUser(appId, userId);
      router.push(`/console/apps/${appId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to delete user");
      setDeleteConfirm(false);
    } finally {
      setDeleting(false);
    }
  };

  if (error && !details) return <ErrorBanner message={error} />;
  if (!app || !details) return <Loading label="Loading user details" />;

  const normalizedHistoryFilter = historyFilter.trim().toLowerCase();
  const filteredHistory = details.history.filter((event) => {
    if (!normalizedHistoryFilter) return true;
    const searchable = [
      event.action,
      formatAction(event.action),
      event.actorType,
      event.ipAddress ?? "",
      event.requestId ?? "",
      event.createdAt,
      formatDateTime(event.createdAt),
      JSON.stringify(event.metadata ?? {}),
    ].join(" ").toLowerCase();
    return searchable.includes(normalizedHistoryFilter);
  });
  const historyTotalPages = Math.ceil(filteredHistory.length / HISTORY_PAGE_SIZE);
  const currentHistoryPage = Math.min(historyPage, Math.max(0, historyTotalPages - 1));
  const historyStart = filteredHistory.length ? currentHistoryPage * HISTORY_PAGE_SIZE + 1 : 0;
  const historyEnd = Math.min((currentHistoryPage + 1) * HISTORY_PAGE_SIZE, filteredHistory.length);
  const pageHistory = filteredHistory.slice(
    currentHistoryPage * HISTORY_PAGE_SIZE,
    (currentHistoryPage + 1) * HISTORY_PAGE_SIZE,
  );

  return <Stack className="user-page-stack">
    <PageHeader title={details.user.name} description={`Application user in ${app.name}.`} actions={<Button variant="quiet" icon="arrowLeft" onClick={() => router.push(`/console/apps/${app.id}`)}>Back to application</Button>} />
    {error && <ErrorBanner message={error} />}
    {revokeAllConfirm && <ConfirmModal busy={pendingSession === "all"} title="Revoke all user sessions?" description="This signs the user out on every device. They can sign in again unless their account is blocked." resourceName={details.user.email} confirmLabel="Revoke sessions" onCancel={() => setRevokeAllConfirm(false)} onConfirm={revokeAllSessions} />}
    {deleteConfirm && <ConfirmModal busy={deleting} title="Delete this user permanently?" description="The user's sessions and role assignments will be removed. This cannot be undone." resourceName={details.user.email} confirmLabel="Delete user" onCancel={() => setDeleteConfirm(false)} onConfirm={deleteUser} />}
    <Card><div className="card-heading"><div><h2>User details</h2><p>Identity and access information for this application user.</p></div><div className="page-actions"><Button variant="danger" onClick={() => setDeleteConfirm(true)}>Delete user</Button><Button variant="secondary" onClick={() => setEditing(!editing)}>{editing ? "Cancel" : "Edit"}</Button></div></div>{editing ? <UserEditor details={details} onCancel={() => setEditing(false)} onSaved={async () => { setEditing(false); await load(); }} /> : <div className="user-page-summary"><div><strong>Name</strong><span>{details.user.name}</span></div><div><strong>Email</strong><span>{details.user.email}</span></div><div><strong>Status</strong><span><StatusBadge value={details.user.status} /></span></div><div><strong>Email verification</strong><span>{details.user.emailVerified ? "Verified" : "Required"}</span></div><div><strong>Created</strong><span>{formatDate(details.user.createdAt)}</span></div><div><strong>Last sign-in</strong><span>{details.user.lastLoginAt ? formatDateTime(details.user.lastLoginAt) : "Not yet"}</span></div><div className="user-page-id"><strong>User ID</strong><span className="mono">{details.user.id}<CopyButton value={details.user.id} /></span></div></div>}</Card>
    <RolesPermissionsManager appId={app.id} applicationName={app.name} assignedRoleIds={details.roles.map((role) => role.id)} mode="user" permissions={permissions} roles={roles} userId={details.user.id} userRolePermissions={details.userRolePermissions} onPermissions={setPermissions} onRoles={setRoles} onUpdated={load} />
    <Card><div className="card-heading"><div><h2>Active sessions ({sessions.length})</h2><p>Sessions currently signed in as this application user.</p></div>{sessions.length > 0 && <Button onClick={() => setRevokeAllConfirm(true)} variant="danger">Revoke all sessions</Button>}</div>{sessionError && <ErrorBanner message={sessionError} />}{sessions.length ? <div className="session-list">{sessions.map((session) => <div className="session-row" key={session.id}><div className="session-row-icon"><Icon name="users" size={18} /></div><div className="session-row-details"><strong>{deviceName(session.userAgent)}</strong><span>{session.ipAddress || "Unknown IP"} · Last active {formatDateTime(session.lastActiveAt)}</span><small>Signed in {formatDateTime(session.createdAt)}</small></div><Button disabled={pendingSession === session.id} onClick={() => revokeSession(session.id)} type="button" variant="quiet">{pendingSession === session.id ? "Revoking…" : "Revoke"}</Button></div>)}</div> : !sessionError && <p className="muted">No active sessions.</p>}</Card>
    <Card className="history-card">
      <button aria-expanded={historyOpen} className="history-page-toggle" onClick={() => setHistoryOpen(!historyOpen)} type="button">
        <span><Icon name={historyOpen ? "chevronDown" : "chevronRight"} size={18} />History ({details.history.length})</span>
      </button>
      {historyOpen && <>
        <div className="history-toolbar">
          <label className="inline-search">
            <Icon name="search" size={16} />
            <input aria-label="Filter user history" onChange={(event) => { setHistoryFilter(event.target.value); setHistoryPage(0); }} placeholder="Filter history" value={historyFilter} />
          </label>
          <span className="history-filter-count">Showing {historyStart}-{historyEnd} of {filteredHistory.length}</span>
          <Pagination ariaLabel="User history pagination" page={currentHistoryPage} pageSize={HISTORY_PAGE_SIZE} totalPages={historyTotalPages} onChange={setHistoryPage} />
        </div>
        {pageHistory.length ? <div className="history-list">{pageHistory.map((event) => <div className="history-item" key={event.id}><strong>{formatAction(event.action)}</strong><span>{formatDateTime(event.createdAt)}</span><small>Actor: {event.actorType} · {event.ipAddress ?? "Unknown source"}</small></div>)}</div> : <p className="muted">{normalizedHistoryFilter ? "No history entries match this filter." : "No activity recorded for this user."}</p>}
      </>}
    </Card>
  </Stack>;
}

function UserEditor({ details, onCancel, onSaved }: { details: AppUserDetails; onCancel: () => void; onSaved: () => Promise<void> }) {
  const [name, setName] = useState(details.user.name); const [status, setStatus] = useState(details.user.status); const [verified, setVerified] = useState(details.user.emailVerified); const [password, setPassword] = useState(""); const [error, setError] = useState(""); const [saving, setSaving] = useState(false);
  const submit = async (event: FormEvent) => { event.preventDefault(); setSaving(true); setError(""); try { const payload: Record<string, unknown> = { name, status, emailVerified: verified }; if (password) payload.password = password; await consoleApi.updateUser(details.user.appId, details.user.id, payload); await onSaved(); } catch (err) { setError(err instanceof Error ? err.message : "Unable to update user"); } finally { setSaving(false); } };
  return <form className="user-editor" onSubmit={submit}>{error && <ErrorBanner message={error} />}<div className="form-grid"><Field label="Name" onChange={(event) => setName(event.target.value)} value={name} /><label className="field"><span className="field-label">Status</span><select onChange={(event) => setStatus(event.target.value)} value={status}><option>ACTIVE</option><option>SUSPENDED</option><option>BLOCKED</option></select></label><label className="field checkbox-field"><input checked={verified} onChange={(event) => setVerified(event.target.checked)} type="checkbox" /><span><strong>Email verified</strong><small>Allow this user to pass email verification checks.</small></span></label><Field hint="Leave blank to keep the current password" label="New password" onChange={(event) => setPassword(event.target.value)} type="password" value={password} /></div><div className="form-actions"><Button onClick={onCancel} type="button" variant="quiet">Cancel</Button><Button disabled={saving} type="submit">{saving ? "Saving…" : "Save changes"}</Button></div></form>;
}

function formatDate(value: string) { return new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(new Date(value)); }
function formatDateTime(value: string) { return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
function formatAction(value: string) { return value.toLowerCase().replaceAll("_", " ").replace(/(^|\s)\S/g, (letter) => letter.toUpperCase()); }
function deviceName(userAgent: string | null) {
  if (!userAgent) return "Unknown device";
  const browser = userAgent.includes("Firefox") ? "Firefox" : userAgent.includes("Edg/") ? "Edge" : userAgent.includes("Chrome/") ? "Chrome" : userAgent.includes("Safari/") ? "Safari" : "Browser";
  const os = userAgent.includes("iPhone") || userAgent.includes("iPad") ? "iOS" : userAgent.includes("Android") ? "Android" : userAgent.includes("Windows") ? "Windows" : userAgent.includes("Mac OS") ? "macOS" : userAgent.includes("Linux") ? "Linux" : "device";
  return `${browser} on ${os}`;
}
