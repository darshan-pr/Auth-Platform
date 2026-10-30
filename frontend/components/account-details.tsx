"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { App } from "../lib/types";
import { Card, CopyButton, InfoLink, StatusBadge } from "./ui";
import { Icon } from "./icon";
import { api, consoleApi } from "../lib/api";
import type { MfaStatus } from "../lib/types";

type AccountView = { id: string; name: string; email: string; platformRole: string; status: string; emailVerified?: boolean };

export function AccountDetails({ account, apps = [], showApplications = false, showMfa = false, mfaScope = "console" }: { account: AccountView; apps?: App[]; showApplications?: boolean; showMfa?: boolean; mfaScope?: "console" | "sa" }) {
  const role = account.platformRole === "SA" ? "Super admin" : "User";
  return <div className="account-stack">
    <Card>
      <div className="card-heading"><div><h2>Profile <InfoLink /></h2><p>Identity, access role, and account status.</p></div></div>
      <dl className="account-key-grid">
        <div><dt>Name</dt><dd>{account.name}</dd></div>
        <div><dt>Email</dt><dd className="account-email" title={account.email}>{account.email}</dd></div>
        <div><dt>Platform role</dt><dd>{role}</dd></div>
        <div><dt>Status</dt><dd><StatusBadge value={account.status} /></dd></div>
        <div className="account-id-field"><dt>Account ID</dt><dd className="account-id-value mono">{account.id}<CopyButton value={account.id} /></dd></div>
      </dl>
    </Card>
    {showMfa && <MfaSettings scope={mfaScope} />}
    <Card>
      <div className="card-heading"><div><h2>Access model</h2><p>How access is scoped and recorded for this account.</p></div></div>
      <div className="access-summary"><div><span className="access-icon"><Icon name="check" size={16} /></span><span><strong>Application-scoped access</strong><small>{account.platformRole === "SA" ? "Can review and manage resources across the platform." : "Can manage only applications owned by this account."}</small></span></div><div><span className="access-icon"><Icon name="check" size={16} /></span><span><strong>Audit coverage</strong><small>Account, application, and credential events are recorded.</small></span></div></div>
    </Card>
    {showApplications && <Card><div className="card-heading"><div><h2>Owned applications</h2><p>{apps.length} application{apps.length === 1 ? "" : "s"} owned by this account.</p></div></div>{apps.length === 0 ? <div className="inline-empty">No applications owned by this account.</div> : <div className="mini-list">{apps.map((app) => <Link href={`/apps/${app.id}`} className="mini-list-row" key={app.id}><span className="app-avatar"><Icon name="apps" size={16} /></span><span><strong>{app.name}</strong><small>{app.ownerEmail}</small></span><span className="mini-list-value">{app.userCount} users <Icon name="chevronRight" size={14} /></span></Link>)}</div>}</Card>}
  </div>;
}

function MfaSettings({ scope }: { scope: "console" | "sa" }) {
  const mfaApi = scope === "sa" ? api : consoleApi;
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { mfaApi.mfaStatus().then(setStatus).catch((err) => setError(err.message)); }, [scope]);
  return <Card><div className="card-heading"><div><h2>Sign-in OTP <InfoLink /></h2><p>After the password is verified, a one-time password is sent to this email address.</p></div>{status && <StatusBadge value={status.required ? "Required" : "Disabled"} />}</div>{error && <div className="error-banner"><Icon name="warning" size={16} />{error}</div>}<p className="mfa-help">OTP protection is mandatory for {scope === "sa" ? "SA" : "console"} accounts. It cannot be disabled from this page.</p></Card>;
}
