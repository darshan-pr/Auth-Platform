"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { ConsoleAccount, ConsoleApp } from "../lib/types";
import { consoleApi } from "../lib/api";
import { Button, Card, EmptyState, ErrorBanner, Loading, MetricCard, PageHeader } from "./ui";
import { Icon } from "./icon";

export function ConsoleOverviewPage() {
  const [account, setAccount] = useState<ConsoleAccount | null>(null); const [apps, setApps] = useState<ConsoleApp[]>([]); const [error, setError] = useState(""); const [loading, setLoading] = useState(true);
  const load = () => { setLoading(true); Promise.all([consoleApi.me(), consoleApi.apps()]).then(([me, ownedApps]) => { setAccount(me); setApps(ownedApps); }).catch((err) => setError(err.message)).finally(() => setLoading(false)); }; useEffect(load, []);
  return <><PageHeader eyebrow="DEVELOPER CONSOLE" title="Workspace overview" description="Manage your applications and identity configuration." actions={<Button variant="secondary" icon="refresh" onClick={load}>Refresh</Button>} />{error && <ErrorBanner message={error} />}{loading ? <Loading label="Loading workspace" /> : account && <><div className="welcome-strip"><div><span className="eyebrow">WELCOME BACK</span><h2>{account.name}</h2><p>{account.email}</p></div><Link className="button button-primary" href="/console/apps">Manage applications <Icon name="chevronRight" size={15} /></Link></div><div className="metric-grid"><MetricCard accent="blue" detail="Owned by your account" icon="apps" label="Applications" value={apps.length} /><MetricCard accent="teal" detail="Console access" icon="shield" label="Account status" value="Active" /><MetricCard accent="violet" detail="Default SDK role" icon="users" label="User model" value="Enabled" /></div><Card><div className="card-heading"><div><h2>Your applications</h2><p>Credentials and settings for your identity integrations</p></div><Link className="text-link" href="/console/apps">View all <Icon name="chevronRight" size={14} /></Link></div>{apps.length === 0 ? <EmptyState title="Create your first application" description="An application gives you publishable keys and an SDK identity boundary." /> : <div className="console-app-grid">{apps.slice(0, 4).map((app) => <Link className="console-app-card" href={`/console/apps/${app.id}`} key={app.id}><span className="app-avatar"><Icon name="apps" size={17} /></span><div><strong>{app.name}</strong><small>{app.allowedOrigins[0] ?? "No origin configured"}</small></div><span className="app-card-arrow"><Icon name="chevronRight" size={15} /></span></Link>)}</div>}</Card></>}</>;
}
