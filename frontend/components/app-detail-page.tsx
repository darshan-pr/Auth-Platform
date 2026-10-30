"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import type { App, AppUser, PageResponse, RotatedSecret } from "../lib/types";
import { api } from "../lib/api";
import { Button, Card, ConfirmModal, CopyButton, ErrorBanner, Field, Loading, PageHeader, Pagination, StatusBadge } from "./ui";
import { Icon } from "./icon";

type AppTab = "configuration" | "users" | "credentials" | "activity";
const appTabLabels: Record<AppTab, string> = {
  configuration: "Configuration",
  users: "End users",
  credentials: "Credentials",
  activity: "Activity",
};

export function AppDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [app, setApp] = useState<App | null>(null);
  const [users, setUsers] = useState<PageResponse<AppUser> | null>(null);
  const [secret, setSecret] = useState<RotatedSecret | null>(null);
  const [editing, setEditing] = useState(false);
  const [rotateConfirm, setRotateConfirm] = useState(false);
  const [activeTab, setActiveTab] = useState<AppTab>("configuration");
  const [error, setError] = useState("");
  const [page, setPage] = useState(0);
  const requestVersion = useRef(0);

  useEffect(() => {
    setApp(null);
    setUsers(null);
    setError("");
  }, [id]);

  const load = () => {
    const currentRequest = ++requestVersion.current;
    setError("");
    Promise.all([api.app(id), api.appUsers(id, page)])
      .then(([nextApp, nextUsers]) => {
        if (currentRequest === requestVersion.current) {
          setApp(nextApp);
          setUsers(nextUsers);
          setError("");
        }
      })
      .catch((err) => {
        if (currentRequest === requestVersion.current) {
          setError(err instanceof Error ? err.message : "Unable to load application");
        }
      });
  };
  useEffect(() => {
    load();
    return () => { requestVersion.current += 1; };
  }, [id, page]);
  if (error && !app) return <><Button variant="quiet" onClick={() => router.push("/apps")}>Applications</Button><ErrorBanner message={error} /></>;
  if (!app || !users) return <Loading label="Loading application" />;

  const rotateSecret = async () => { try { setSecret(await api.rotateSecret(app.id)); } catch (err) { setError(err instanceof Error ? err.message : "Unable to rotate secret"); } finally { setRotateConfirm(false); } };
  return <><PageHeader browserTitle={`${app.name} - ${appTabLabels[activeTab]}`} title={app.name} description={`Owned by ${app.ownerEmail}`} />{error && <ErrorBanner message={error} />}{secret && <div className="secret-banner"><div><strong>New secret key</strong><span>Copy it now. It will not be shown again.</span></div><code>{secret.secretKey}</code><CopyButton value={secret.secretKey} /></div>}{rotateConfirm && <ConfirmModal title="Rotate secret key?" description="The current secret will stop working immediately. This action is recorded in the audit trail." resourceName={app.name} confirmLabel="Rotate secret" onCancel={() => setRotateConfirm(false)} onConfirm={rotateSecret} />}<div className="tabs" role="tablist"><button className={activeTab === "configuration" ? "tab-active" : ""} onClick={() => setActiveTab("configuration")} role="tab" type="button">Configuration</button><button className={activeTab === "users" ? "tab-active" : ""} onClick={() => setActiveTab("users")} role="tab" type="button">End users</button><button className={activeTab === "credentials" ? "tab-active" : ""} onClick={() => setActiveTab("credentials")} role="tab" type="button">Credentials</button><button className={activeTab === "activity" ? "tab-active" : ""} onClick={() => setActiveTab("activity")} role="tab" type="button">Activity</button></div>{activeTab === "configuration" && (editing ? <AppEditor app={app} onSaved={(next) => { setApp(next); setEditing(false); }} /> : <Card><div className="card-heading"><div><h2>Configuration</h2><p>Runtime settings and allowed origins.</p></div><Button variant="secondary" onClick={() => setEditing(true)}>Edit settings</Button></div><dl className="detail-list"><div><dt>Owner</dt><dd>{app.ownerEmail}</dd></div><div><dt>End users</dt><dd>{users.totalItems}</dd></div><div><dt>Email verification</dt><dd>{app.requireEmailVerification ? "Required" : "Optional"}</dd></div><div><dt>Access-token lifetime</dt><dd>{app.accessTokenTtlSeconds == null ? "Platform default" : formatTokenLifetime(app.accessTokenTtlSeconds)}</dd></div><div><dt>Refresh-session lifetime</dt><dd>{app.refreshTokenTtlSeconds == null ? "Platform default" : formatTokenLifetime(app.refreshTokenTtlSeconds)}</dd></div><div><dt>Status</dt><dd><StatusBadge value={app.status} /></dd></div><div><dt>Allowed origins</dt><dd><div className="origin-list">{app.allowedOrigins.map((origin) => <span key={origin}>{origin}</span>)}</div></dd></div></dl></Card>)}{activeTab === "users" && <Card><div className="card-heading"><div><h2>End users</h2><p>Users registered against this application.</p></div><Button variant="secondary" icon="refresh" onClick={() => load()}>Refresh</Button></div>{users.items.length === 0 ? <div className="inline-empty">No end users registered yet.</div> : <div className="mini-list">{users.items.map((user) => <div className="mini-list-row" key={user.id}><span className="user-avatar">{user.name.charAt(0).toUpperCase()}</span><span><strong>{user.name}</strong><small>{user.email}</small></span><StatusBadge value={user.status} /></div>)}</div>}<Pagination page={users.page} totalPages={users.totalPages} onChange={setPage} /></Card>}{activeTab === "credentials" && <Card><div className="card-heading"><div><h2>Credentials</h2><p>Keys used by this application. Secrets are masked by default.</p></div><Button variant="danger" onClick={() => setRotateConfirm(true)}>Rotate secret</Button></div><div className="credential-grid"><div className="credential-row"><div><strong>Publishable key</strong><small>Safe to use in browser integrations.</small></div><span className="credential-value">{app.publishableKey}</span><CopyButton value={app.publishableKey} label="Copy key" /></div><div className="credential-row"><div><strong>Secret key</strong><small>Only shown after creation or rotation.</small></div><span className="credential-value">{app.secretKeyHint ?? "Stored securely"}</span></div></div></Card>}{activeTab === "activity" && <Card><div className="card-heading"><div><h2>Activity</h2><p>Application changes and credential events are recorded in the audit trail.</p></div><Button variant="secondary" icon="refresh" onClick={() => load()}>Refresh</Button></div><div className="inline-empty">Application activity will appear here as the activity API is connected.</div></Card>}</>;
}

function AppEditor({ app, onSaved }: { app: App; onSaved: (app: App) => void }) {
  const [name, setName] = useState(app.name); const [status, setStatus] = useState(app.status); const [origins, setOrigins] = useState(app.allowedOrigins.join("\n")); const [verification, setVerification] = useState(app.requireEmailVerification); const [usePlatformTokenTtls, setUsePlatformTokenTtls] = useState(app.accessTokenTtlSeconds == null && app.refreshTokenTtlSeconds == null); const [accessMinutes, setAccessMinutes] = useState(app.accessTokenTtlSeconds == null ? "" : String(app.accessTokenTtlSeconds / 60)); const [refreshHours, setRefreshHours] = useState(app.refreshTokenTtlSeconds == null ? "" : String(app.refreshTokenTtlSeconds / 3600)); const [error, setError] = useState(""); const [saving, setSaving] = useState(false);
  const submit = async (event: React.FormEvent) => { event.preventDefault(); setSaving(true); setError(""); try { const tokenSettings = usePlatformTokenTtls ? { usePlatformTokenTtls: true } : { usePlatformTokenTtls: false, accessTokenTtlSeconds: Math.round(Number(accessMinutes) * 60), refreshTokenTtlSeconds: Math.round(Number(refreshHours) * 3600) }; const result = await api.updateApp(app.id, { name, status, allowedOrigins: origins.split("\n").map((item) => item.trim()).filter(Boolean), requireEmailVerification: verification, ...tokenSettings }); onSaved(result); } catch (err) { setError(err instanceof Error ? err.message : "Unable to update application"); } finally { setSaving(false); } };
  return <Card className="editor-card"><div className="card-heading"><div><h2>Edit settings</h2><p>Changes are recorded in the audit trail.</p></div></div>{error && <ErrorBanner message={error} />}<form onSubmit={submit}><div className="form-grid"><Field label="Application name" onChange={(e) => setName(e.target.value)} value={name} /><label className="field"><span className="field-label">Status</span><select onChange={(e) => setStatus(e.target.value)} value={status}><option>ACTIVE</option><option>SUSPENDED</option></select></label><label className="field checkbox-field"><input checked={verification} onChange={(e) => setVerification(e.target.checked)} type="checkbox" /><span><strong>Require email verification</strong><small>Users must verify before logging in.</small></span></label><label className="field checkbox-field span-2"><input checked={usePlatformTokenTtls} onChange={(e) => setUsePlatformTokenTtls(e.target.checked)} type="checkbox" /><span><strong>Use platform-default token lifetimes</strong><small>Active sessions keep their current expiry.</small></span></label>{!usePlatformTokenTtls && <><Field label="Access-token lifetime (minutes)" type="number" min={1} max={1440} step="any" required onChange={(e) => setAccessMinutes(e.target.value)} value={accessMinutes} /><Field label="Refresh-session lifetime (hours)" type="number" min={1} max={2160} step="any" required onChange={(e) => setRefreshHours(e.target.value)} value={refreshHours} /><p className="field-hint span-2">Access: 1 minute–24 hours. Refresh: 1 hour–90 days and must be at least as long as the access lifetime.</p></>}<label className="field span-2"><span className="field-label">Allowed origins</span><textarea onChange={(e) => setOrigins(e.target.value)} rows={4} value={origins} /></label></div><div className="form-actions"><Button onClick={() => onSaved(app)} type="button" variant="quiet">Cancel</Button><Button disabled={saving} type="submit">{saving ? "Saving…" : "Save changes"}</Button></div></form></Card>;
}

function formatTokenLifetime(seconds: number): string {
  if (seconds % 86_400 === 0) return `${seconds / 86_400} days`;
  if (seconds % 3_600 === 0) return `${seconds / 3_600} hours`;
  if (seconds % 60 === 0) return `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}
