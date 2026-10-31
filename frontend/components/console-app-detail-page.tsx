"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import type { ConsoleApp, Permission, Role, RotatedSecret } from "../lib/types";
import { consoleApi } from "../lib/api";
import { Button, Card, ConfirmModal, CopyButton, ErrorBanner, Field, Loading, PageHeader, Stack, StatusBadge } from "./ui";
import { EndUsersTable } from "./end-users-table";
import { InviteUsersModal } from "./invite-users-modal";
import { RolesPermissionsManager } from "./roles-permissions-manager";
import { Icon } from "./icon";
import { AppIconPanel } from "./app-icon-panel";

type AppTab = "configuration" | "roles" | "users" | "credentials" | "activity";
const appTabLabels: Record<AppTab, string> = {
  configuration: "Configuration",
  roles: "Roles and permissions",
  users: "End users",
  credentials: "Credentials",
  activity: "Activity",
};

export function ConsoleAppDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [app, setApp] = useState<ConsoleApp | null>(null);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<AppTab>("configuration");
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [editing, setEditing] = useState(false);
  const [secret, setSecret] = useState<RotatedSecret | null>(null);
  const [rotateConfirm, setRotateConfirm] = useState(false);
  const applicationIcon = app?.iconDataUrl || app?.iconUrl;

  useEffect(() => {
    let active = true;
    setApp(null);
    setRoles([]);
    setPermissions([]);
    setError("");
    consoleApi.app(id)
      .then((nextApp) => {
        if (active) setApp(nextApp);
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : "Unable to load application");
      });
    return () => { active = false; };
  }, [id]);
  useEffect(() => updateApplicationFavicon(applicationIcon), [applicationIcon]);
  useEffect(() => {
    if (!app || app.id !== id) return;
    let active = true;
    Promise.all([consoleApi.roles(app.id), consoleApi.permissions(app.id)])
      .then(([nextRoles, nextPermissions]) => {
        if (active) {
          setRoles(nextRoles);
          setPermissions(nextPermissions);
        }
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : "Unable to load application roles and permissions");
      });
    return () => { active = false; };
  }, [app?.id, id]);

  if (!app && !error) return <Loading label="Loading application" />;
  if (error && !app) return <><Button variant="quiet" icon="arrowLeft" onClick={() => router.push("/console/apps")}>Back to applications</Button><ErrorBanner message={error} /></>;
  if (!app) return null;

  const rotateSecret = async () => {
    try { setSecret(await consoleApi.rotateSecret(app.id)); } catch (err) { setError(err instanceof Error ? err.message : "Unable to rotate secret"); } finally { setRotateConfirm(false); }
  };

  return <Stack className="app-detail-stack">
    <PageHeader browserTitle={`${app.name} - ${appTabLabels[activeTab]}`} title={<span className="app-page-title">{applicationIcon && <img alt="" src={applicationIcon} />}<span>{app.name}</span></span>} description="Credentials, users, and identity configuration for this application." />
    {error && <ErrorBanner message={error} />}
    {secret && <div className="secret-banner"><div><strong>New secret key</strong><span>Copy it now. It will not be shown again.</span></div><code>{secret.secretKey}</code><CopyButton value={secret.secretKey} label="Copy secret" /></div>}
    {rotateConfirm && <ConfirmModal title="Rotate secret key?" description="The current secret will stop working immediately. This action is recorded in the audit trail." resourceName={app.name} confirmLabel="Rotate secret" onCancel={() => setRotateConfirm(false)} onConfirm={rotateSecret} />}
    <Card className="summary-card"><div className="card-heading"><div><h2>Summary</h2><p>Application identity and current operating state.</p></div></div><div className="summary-grid"><div><strong>Application ID</strong><span className="mono account-id-value">{app.id}<CopyButton value={app.id} /></span></div><div><strong>Default role</strong><span>{app.defaultRole.name}</span></div><div><strong>Email verification</strong><span>{app.requireEmailVerification ? "Required" : "Optional"}</span></div><div><strong>Email OTP</strong><span>{app.mfaRequired ? "Required" : "Disabled"}</span></div><div><strong>Status</strong><span><StatusBadge value={app.status} /></span></div></div></Card>
    <nav className="tabs app-feature-tabs" aria-label="Application features" role="tablist"><AppTabButton active={activeTab === "configuration"} onClick={() => setActiveTab("configuration")}>Configuration</AppTabButton><AppTabButton active={activeTab === "roles"} onClick={() => setActiveTab("roles")}>Roles &amp; permissions</AppTabButton><AppTabButton active={activeTab === "users"} onClick={() => setActiveTab("users")}>End users</AppTabButton><AppTabButton active={activeTab === "credentials"} onClick={() => setActiveTab("credentials")}>Credentials</AppTabButton><AppTabButton active={activeTab === "activity"} onClick={() => setActiveTab("activity")}>Activity</AppTabButton></nav>
    {activeTab === "configuration" && <ConfigurationPanel app={app} editing={editing} onEdit={() => setEditing(true)} onCancel={() => setEditing(false)} onSaved={(next) => { setApp(next); setEditing(false); }} onAppUpdated={setApp} />}
    {activeTab === "roles" && <RolesPermissionsManager appId={app.id} applicationName={app.name} mode="app" permissions={permissions} roles={roles} onPermissions={setPermissions} onRoles={setRoles} />}
    {activeTab === "users" && <UsersPanel appId={app.id} appName={app.name} />}
    {activeTab === "credentials" && <Card><div className="card-heading"><div><h2>Credentials</h2><p>Keys used by this application. Secrets are masked by default.</p></div><Button variant="danger" onClick={() => setRotateConfirm(true)}>Rotate secret</Button></div><div className="credential-grid"><div className="credential-row"><div><strong>Publishable key</strong><small>Safe to use in browser integrations.</small></div><CopyButton value={app.publishableKey} label="Copy key" /></div><div className="credential-row"><div><strong>Secret key</strong><small>Only shown after creation or rotation.</small></div><span className="credential-value">{app.secretKeyHint ?? "Stored securely"}</span></div></div></Card>}
    {activeTab === "activity" && <Card><div className="card-heading"><div><h2>Activity</h2><p>Application changes and credential events are recorded in the audit trail.</p></div></div><div className="inline-empty">Application activity will appear here as the activity API is connected.</div></Card>}
  </Stack>;
}

function updateApplicationFavicon(iconUrl?: string | null): (() => void) | undefined {
  if (!iconUrl) return undefined;
  const currentLinks = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel~="icon"]'));
  const createdLink = currentLinks.length === 0;
  const links = createdLink ? [document.createElement("link")] : currentLinks;
  const originals = links.map((link) => ({
    link,
    href: link.getAttribute("href"),
    type: link.getAttribute("type")
  }));
  const mimeType = /^data:(image\/[a-z0-9.+-]+);/i.exec(iconUrl)?.[1];
  if (createdLink) links[0].rel = "icon";
  for (const link of links) {
    link.setAttribute("href", iconUrl);
    if (mimeType) link.setAttribute("type", mimeType);
    else link.removeAttribute("type");
  }
  if (createdLink) document.head.append(links[0]);
  return () => {
    if (createdLink) {
      links[0].remove();
      return;
    }
    for (const original of originals) {
      if (original.href === null) original.link.removeAttribute("href");
      else original.link.setAttribute("href", original.href);
      if (original.type === null) original.link.removeAttribute("type");
      else original.link.setAttribute("type", original.type);
    }
  };
}

function AppTabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) { return <button aria-selected={active} className={active ? "tab-active" : ""} onClick={onClick} role="tab" type="button">{children}</button>; }

function ConfigurationPanel({ app, editing, onEdit, onCancel, onSaved, onAppUpdated }: { app: ConsoleApp; editing: boolean; onEdit: () => void; onCancel: () => void; onSaved: (app: ConsoleApp) => void; onAppUpdated: (app: ConsoleApp) => void }) {
  const verifyEmailUrl = app.verifyEmailUrl || "Uses first allowed origin + /verify-email";
  return <>
    {editing ? <ConsoleAppEditor app={app} onCancel={onCancel} onSaved={onSaved} /> : <Card><div className="card-heading"><div><h2>Application configuration</h2><p>Email verification, origins, token lifetimes, and runtime behavior.</p></div><Button variant="secondary" onClick={onEdit}>Edit</Button></div><div className="application-config-grid"><div><strong>Email verification</strong><span>{app.requireEmailVerification ? "Required" : "Optional"}</span></div><div><strong>Status</strong><span><StatusBadge value={app.status} /></span></div><div><strong>Default role</strong><span>{app.defaultRole.name}</span></div><div><strong>Email OTP</strong><span>{app.mfaRequired ? "Required" : "Disabled"}</span></div><div><strong>Access-token lifetime</strong><span>{app.accessTokenTtlSeconds == null ? "Platform default" : formatTokenLifetime(app.accessTokenTtlSeconds)}</span></div><div><strong>Refresh-session lifetime</strong><span>{app.refreshTokenTtlSeconds == null ? "Platform default" : formatTokenLifetime(app.refreshTokenTtlSeconds)}</span></div><div className="application-config-url"><strong>Verify email URL</strong><span className="mono" title={verifyEmailUrl}>{verifyEmailUrl}</span></div><div><strong>Allowed origins</strong><span className="origin-list">{app.allowedOrigins.map((origin) => <span key={origin}>{origin}</span>)}</span></div></div></Card>}
    <AppIconPanel app={app} onUpdated={onAppUpdated} />
  </>;
}

function UsersPanel({ appId, appName }: { appId: string; appName: string }) {
  const [inviting, setInviting] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  return <>
    {inviting && <InviteUsersModal appId={appId} appName={appName} onClose={() => setInviting(false)} onInvited={() => setReloadKey((key) => key + 1)} />}
    <EndUsersTable mode="console" appId={appId} description="Open a user to manage their details, roles, permissions, and history." headerActions={<Button icon="plus" onClick={() => setInviting(true)}>Invite users</Button>} reloadKey={reloadKey} />
  </>;
}

function ConsoleAppEditor({ app, onSaved, onCancel }: { app: ConsoleApp; onSaved: (app: ConsoleApp) => void; onCancel: () => void }) {
  const [name, setName] = useState(app.name); const [status, setStatus] = useState(app.status); const [origins, setOrigins] = useState(app.allowedOrigins.join("\n")); const [verifyEmailUrl, setVerifyEmailUrl] = useState(app.verifyEmailUrl ?? ""); const [verification, setVerification] = useState(app.requireEmailVerification); const [mfaRequired, setMfaRequired] = useState(app.mfaRequired); const [usePlatformTokenTtls, setUsePlatformTokenTtls] = useState(app.accessTokenTtlSeconds == null && app.refreshTokenTtlSeconds == null); const [accessMinutes, setAccessMinutes] = useState(app.accessTokenTtlSeconds == null ? "" : String(app.accessTokenTtlSeconds / 60)); const [refreshHours, setRefreshHours] = useState(app.refreshTokenTtlSeconds == null ? "" : String(app.refreshTokenTtlSeconds / 3600)); const [error, setError] = useState(""); const [saving, setSaving] = useState(false);
  const submit = async (event: FormEvent) => { event.preventDefault(); setSaving(true); setError(""); try { const tokenSettings = usePlatformTokenTtls ? { usePlatformTokenTtls: true } : { usePlatformTokenTtls: false, accessTokenTtlSeconds: Math.round(Number(accessMinutes) * 60), refreshTokenTtlSeconds: Math.round(Number(refreshHours) * 3600) }; onSaved(await consoleApi.updateApp(app.id, { name, status, allowedOrigins: origins.split("\n").map((item) => item.trim()).filter(Boolean), verifyEmailUrl, requireEmailVerification: verification, mfaRequired, ...tokenSettings })); } catch (err) { setError(err instanceof Error ? err.message : "Unable to update application"); } finally { setSaving(false); } };
  return <Card><div className="card-heading"><div><h2>Edit application</h2><p>Changes are recorded in the audit trail.</p></div></div>{error && <ErrorBanner message={error} />}<form onSubmit={submit}><div className="form-grid"><Field label="Application name" onChange={(event) => setName(event.target.value)} value={name} /><label className="field"><span className="field-label">Status</span><select onChange={(event) => setStatus(event.target.value)} value={status}><option>ACTIVE</option><option>SUSPENDED</option></select></label><label className="field checkbox-field"><input checked={verification} onChange={(event) => setVerification(event.target.checked)} type="checkbox" /><span><strong>Require email verification</strong><small>Users must verify before logging in.</small></span></label><label className="field checkbox-field"><input checked={mfaRequired} onChange={(event) => setMfaRequired(event.target.checked)} type="checkbox" /><span><strong>Require email OTP for app users</strong><small>After a correct password, users receive a one-time password by email.</small></span></label><label className="field checkbox-field span-2"><input checked={usePlatformTokenTtls} onChange={(event) => setUsePlatformTokenTtls(event.target.checked)} type="checkbox" /><span><strong>Use platform-default token lifetimes</strong><small>Changes apply to new sessions; active sessions keep their current expiry.</small></span></label>{!usePlatformTokenTtls && <><Field label="Access-token lifetime (minutes)" type="number" min={1} max={1440} step="any" required onChange={(event) => setAccessMinutes(event.target.value)} value={accessMinutes} /><Field label="Refresh-session lifetime (hours)" type="number" min={1} max={2160} step="any" required onChange={(event) => setRefreshHours(event.target.value)} value={refreshHours} /><p className="field-hint span-2">Access: 1 minute–24 hours. Refresh: 1 hour–90 days and must be at least as long as the access lifetime.</p></>}<Field className="span-2" hint="For the local SDK test app, set this to http://localhost:3001/verify-email." label="Verify email URL" onChange={(event) => setVerifyEmailUrl(event.target.value)} placeholder="https://app.example.com/verify-email" value={verifyEmailUrl} /><label className="field span-2"><span className="field-label">Allowed origins</span><textarea onChange={(event) => setOrigins(event.target.value)} rows={4} value={origins} /><span className="field-hint">For the local SDK test app, include http://localhost:3001.</span></label></div><div className="form-actions"><Button onClick={onCancel} type="button" variant="quiet">Cancel</Button><Button disabled={saving} type="submit">{saving ? "Saving…" : "Save changes"}</Button></div></form></Card>;
}

function formatTokenLifetime(seconds: number): string {
  if (seconds % 86_400 === 0) return `${seconds / 86_400} days`;
  if (seconds % 3_600 === 0) return `${seconds / 3_600} hours`;
  if (seconds % 60 === 0) return `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}
