"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { Analytics } from "../lib/types";
import { api } from "../lib/api";
import { Card, EmptyState, ErrorBanner, Loading, MetricCard, PageHeader, Button } from "./ui";
import { Icon } from "./icon";

export function OverviewPage() {
  const [data, setData] = useState<Analytics | null>(null);
  const [health, setHealth] = useState<{ status: string; components?: Record<string, { status: string }> } | null>(null);
  const [error, setError] = useState("");
  const [healthError, setHealthError] = useState("");
  const [loading, setLoading] = useState(true);
  const refreshHealth = () => api.health()
    .then((nextHealth) => { setHealth(nextHealth); setHealthError(""); })
    .catch((err) => {
      setHealth(null);
      setHealthError(err instanceof Error ? err.message : "Unable to load dependency health.");
    });
  const load = () => {
    setLoading(true);
    setError("");
    const analyticsRequest = api.analytics()
      .then(setData)
      .catch((err) => setError(err instanceof Error ? err.message : "Unable to load platform metrics."));
    Promise.all([analyticsRequest, refreshHealth()]).finally(() => setLoading(false));
  };
  useEffect(() => {
    load();
    const interval = window.setInterval(() => { void refreshHealth(); }, 30_000);
    return () => window.clearInterval(interval);
  }, []);

  return <><PageHeader eyebrow="PLATFORM OVERVIEW" title="Overview" description="A live view of identity activity across the platform." actions={<Button variant="secondary" icon="refresh" onClick={load}>Refresh</Button>} />{error && <ErrorBanner message={error} />}{healthError && <ErrorBanner message={`Dependency health check failed: ${healthError}`} />}{loading ? <Loading label="Loading platform metrics" /> : data && <>
    <div className="metric-grid"><MetricCard accent="blue" detail={`${data.activeAccounts} active`} icon="users" label="Accounts" value={data.totalAccounts} /><MetricCard accent="violet" detail={`${data.activeApps} active`} icon="apps" label="Applications" value={data.totalApps} /><MetricCard accent="teal" detail={`${data.activeAppUsers} active`} icon="users" label="End users" value={data.totalAppUsers} /><MetricCard accent="amber" detail={`${data.verifiedAccounts} verified`} icon="shield" label="Verified accounts" value={data.verifiedAccounts} /></div>
    <div className="content-grid overview-grid"><Card><div className="card-heading"><div><h2>User distribution</h2><p>Registered end users by application</p></div><Link href="/users" className="text-link">View all <Icon name="chevronRight" size={14} /></Link></div>{data.usersByApp.length === 0 ? <EmptyState title="No application users yet" description="User distribution will appear as applications receive signups." /> : <div className="distribution-list">{data.usersByApp.map((app, index) => <div className="distribution-row" key={app.appId}><div className="distribution-label"><span className={`rank rank-${index + 1}`}>{index + 1}</span><Link href={`/apps/${app.appId}`}>{app.appName}</Link></div><div className="distribution-track"><span style={{ width: `${Math.max(4, data.totalAppUsers ? (app.userCount / data.totalAppUsers) * 100 : 0)}%` }} /></div><strong>{app.userCount}</strong></div>)}</div>}</Card><Card className="activity-card"><div className="card-heading"><div><h2>Operational health</h2><p>Live dependency checks</p></div><span className="health-pill"><span className="online-dot" />{health?.status ?? "Unknown"}</span></div><div className="health-list"><HealthRow label="Authentication service" status={health?.status ?? "UNKNOWN"} detail="Backend health endpoint" /><HealthRow label="Database connection" status={health?.components?.db?.status ?? "UNKNOWN"} detail="PostgreSQL health indicator" /><HealthRow label="Redis connection" status={health?.components?.redis?.status ?? "UNKNOWN"} detail="Redis health indicator" /></div></Card></div>
    <Card className="quick-actions"><div className="card-heading"><div><h2>Common tasks</h2><p>Jump into the areas you use most</p></div></div><div className="quick-action-grid"><Link href="/accounts" className="quick-action"><span><Icon name="users" size={19} /></span><strong>Review accounts</strong><small>Inspect account status and access</small><Icon name="chevronRight" size={15} /></Link><Link href="/apps" className="quick-action"><span><Icon name="apps" size={19} /></span><strong>Manage applications</strong><small>Review apps and rotate credentials</small><Icon name="chevronRight" size={15} /></Link><Link href="/audit-logs" className="quick-action"><span><Icon name="audit" size={19} /></span><strong>Review audit logs</strong><small>See the latest platform changes</small><Icon name="chevronRight" size={15} /></Link></div></Card>
  </>}</>;
}

function StatusText({ value }: { value: string }) { return <span className="status-text">{value}</span>; }
function HealthRow({ label, status, detail }: { label: string; status: string; detail: string }) { const ok = status === "UP"; return <div><span className={`health-icon ${ok ? "health-ok" : "health-fail"}`}>{ok ? "✓" : "!"}</span><span><strong>{label}</strong><small>{detail}</small></span><StatusText value={ok ? "Operational" : status} /></div>; }
