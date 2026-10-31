"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";
import type { App, AppUser } from "../lib/types";
import { api, consoleApi } from "../lib/api";
import { useServerList } from "../lib/use-server-list";
import { Button, Card, ConfirmModal, ErrorBanner, InfoLink, Loading, Pagination, SortHeader, StatusBadge, TableControls } from "./ui";
import { Icon } from "./icon";

type SortKey = "name" | "email" | "status" | "emailVerified" | "lastLoginAt";
type Mode = "sa" | "console";

const statusOptions = [
  { value: "", label: "All statuses" },
  { value: "ACTIVE", label: "Active" },
  { value: "INVITED", label: "Invited" },
  { value: "UNVERIFIED", label: "Unverified" },
  { value: "SUSPENDED", label: "Suspended" },
  { value: "BLOCKED", label: "Blocked" },
];

/**
 * The end-user table shared by the SA "End users" page (every application) and the console
 * application's "End users" tab (one application). Search, status filter, sorting and paging
 * all run on the server so they cover every user, not only the rows on screen.
 */
export function EndUsersTable({
  mode,
  appId,
  apps = [],
  onAppChange,
  initialQuery = "",
  description,
  headerActions,
  reloadKey = 0,
  onLoaded,
}: {
  mode: Mode;
  appId?: string;
  apps?: App[];
  onAppChange?: (appId: string) => void;
  initialQuery?: string;
  description: string;
  headerActions?: ReactNode;
  reloadKey?: number;
  onLoaded?: (total: number) => void;
}) {
  const router = useRouter();
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<AppUser | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [resendingId, setResendingId] = useState("");
  const showApplication = mode === "sa";
  const scopedAppId = mode === "console" ? appId : appId && appId !== "all" ? appId : undefined;
  const list = useServerList<AppUser, SortKey>({
    tableId: "end-users",
    initialQuery,
    initialSort: { key: "name", direction: "asc" },
    deps: [mode, appId, scopedAppId, status, reloadKey],
    fetchPage: (page, params) => {
      const query = { ...params, status };
      return mode === "console"
        ? consoleApi.endUsers(appId ?? "", page, query)
        : scopedAppId ? api.appUsers(scopedAppId, page, query) : api.users(page, query);
    },
  });
  const { items: users, page, setPage, totalPages, totalItems, pageSize, filter, setFilter, query, sortKey, sortDirection, toggleSort, loading } = list;
  const onLoadedRef = useRef(onLoaded);
  onLoadedRef.current = onLoaded;
  useEffect(() => { onLoadedRef.current?.(totalItems); }, [totalItems]);

  const revokeUserSessions = async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    setError("");
    setNotice("");
    try {
      if (mode === "console") await consoleApi.revokeAllAppUserSessions(revokeTarget.appId, revokeTarget.id);
      else await api.revokeAllAppUserSessions(revokeTarget.appId, revokeTarget.id);
      setNotice(`Revoked active sessions for ${revokeTarget.name}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to revoke user sessions");
    } finally {
      setRevoking(false);
      setRevokeTarget(null);
    }
  };

  const resendInvitation = async (user: AppUser) => {
    setResendingId(user.id);
    setError("");
    setNotice("");
    try {
      await consoleApi.resendInvitation(user.appId, user.id);
      setNotice(`Sent a new invitation to ${user.email}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to resend the invitation");
    } finally {
      setResendingId("");
    }
  };

  const columnCount = showApplication ? 6 : 5;
  const filtered = Boolean(query || status);
  return <>
    {(error || list.error) && <ErrorBanner message={error || list.error} />}
    {notice && <p className="session-success" role="status">{notice}</p>}
    {revokeTarget && <ConfirmModal busy={revoking} title="Revoke this user's sessions?" description="This signs the user out on every device. They can sign in again unless their account is blocked." resourceName={revokeTarget.email} confirmLabel="Revoke sessions" onCancel={() => setRevokeTarget(null)} onConfirm={revokeUserSessions} />}
    <Card>
      <div className="table-heading"><div><div className="table-title"><h2>End users ({totalItems})</h2><InfoLink /></div><p>{description}</p></div>{headerActions}</div>
      <div className="toolbar">
        <div className="filter-group">
          {showApplication && <label className="select-filter"><span>Application</span><select onChange={(event) => { onAppChange?.(event.target.value); setPage(0); }} value={appId ?? "all"}><option value="all">All applications</option>{apps.map((app) => <option key={app.id} value={app.id}>{app.name}</option>)}</select></label>}
          <label className="select-filter"><span>Status</span><select onChange={(event) => { setStatus(event.target.value); setPage(0); }} value={status}>{statusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
        </div>
        <div className="table-toolbar-actions">
          <label className="inline-search"><Icon name="search" size={16} /><input aria-label="Filter users" onChange={(event) => setFilter(event.target.value)} placeholder="Filter users" value={filter} /></label>
          <Pagination page={page} totalPages={totalPages} pageSize={pageSize} onChange={setPage} />
          <TableControls tableId="end-users" />
        </div>
      </div>
      {loading && users.length === 0 ? <Loading label="Loading end users" /> : <div className="table-wrap" aria-busy={loading}><table><thead><tr>
        <th><SortHeader label="User" active={sortKey === "name"} direction={sortDirection} onClick={() => toggleSort("name")} /></th>
        {showApplication && <th>Application</th>}
        <th><SortHeader label="Status" active={sortKey === "status"} direction={sortDirection} onClick={() => toggleSort("status")} /></th>
        <th><SortHeader label="Verification" active={sortKey === "emailVerified"} direction={sortDirection} onClick={() => toggleSort("emailVerified")} /></th>
        <th><SortHeader label="Last login" active={sortKey === "lastLoginAt"} direction={sortDirection} onClick={() => toggleSort("lastLoginAt")} /></th>
        <th>Actions</th></tr></thead>
        <tbody>{users.map((user) => <tr key={user.id}>
          <td>{mode === "console" ? <button className="table-primary table-link-button" onClick={() => router.push(`/console/apps/${user.appId}/users/${user.id}`)} type="button">{user.name}</button> : <span className="table-primary">{user.name}</span>}<span className="table-secondary">{user.email}</span></td>
          {showApplication && <td><span className="mono">{user.appId.slice(0, 12)}…</span></td>}
          <td><StatusBadge value={user.invited && user.status === "ACTIVE" ? "INVITED" : user.status} /></td>
          <td>{user.emailVerified ? <span className="verified-mark">Verified</span> : <span className="muted">Pending</span>}</td>
          <td className="muted">{user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleDateString() : "Never"}</td>
          <td><div className="table-actions">
            {mode === "console" && user.invited && <button aria-label={`Resend invitation to ${user.email}`} className="table-icon-button" disabled={resendingId === user.id} onClick={() => resendInvitation(user)} title="Resend invitation" type="button"><Icon name="mail" size={16} /></button>}
            <button aria-label={`Revoke ${user.name}'s sessions`} className="table-icon-button" disabled={revoking} onClick={() => setRevokeTarget(user)} title="Revoke active sessions" type="button"><Icon name="logout" size={16} /></button>
          </div></td>
        </tr>)}
        {users.length === 0 && <tr><td colSpan={columnCount}><div className="table-empty">{filtered ? "No users match this filter." : mode === "console" ? "No end users yet. Invite people or wait for sign-ups." : "No end users yet."}{filtered && <> <Button variant="quiet" onClick={() => { list.clearFilter(); setStatus(""); }}>Clear filters</Button></>}</div></td></tr>}</tbody></table></div>}
    </Card>
  </>;
}
