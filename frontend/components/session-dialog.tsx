"use client";

import type { SessionInfo } from "../lib/types";
import { Button, ErrorBanner } from "./ui";
import { Icon } from "./icon";

export function SessionDialog({
  sessions,
  error,
  pendingId,
  signingOut,
  onCancel,
  onRevoke,
  onSignOut,
}: {
  sessions: SessionInfo[];
  error: string;
  pendingId: string;
  signingOut: boolean;
  onCancel: () => void;
  onRevoke: (session: SessionInfo) => void;
  onSignOut: () => void;
}) {
  return <div className="modal-backdrop session-modal-backdrop"><section aria-labelledby="sessions-title" aria-modal="true" className="modal session-modal" role="dialog">
    <div className="modal-header"><div><h2 id="sessions-title">Signed-in devices</h2><p>Review other active sessions before signing out.</p></div><button aria-label="Close session dialog" className="icon-button" onClick={onCancel} type="button"><Icon name="close" /></button></div>
    {error && <ErrorBanner message={error} />}
    <div className="session-list">{sessions.map((session) => <div className="session-row" key={session.id}>
      <div className="session-row-icon"><Icon name="users" size={18} /></div>
      <div className="session-row-details"><strong>{deviceName(session.userAgent)}{session.current && <span className="session-current-badge">This device</span>}</strong><span>{session.ipAddress || "Unknown IP"} · Last active {formatSessionDate(session.lastActiveAt)}</span><small>Signed in {formatSessionDate(session.createdAt)}</small></div>
      {!session.current && <Button disabled={pendingId === session.id} onClick={() => onRevoke(session)} type="button" variant="quiet">{pendingId === session.id ? "Revoking…" : "Revoke"}</Button>}
    </div>)}</div>
    <div className="modal-actions"><Button disabled={signingOut} onClick={onCancel} type="button" variant="quiet">Stay signed in</Button><Button disabled={signingOut} onClick={onSignOut} type="button" variant="danger">{signingOut ? "Signing out…" : "Sign out here"}</Button></div>
  </section></div>;
}

function deviceName(userAgent: string | null) {
  if (!userAgent) return "Unknown device";
  const browser = userAgent.includes("Firefox") ? "Firefox" : userAgent.includes("Edg/") ? "Edge" : userAgent.includes("Chrome/") ? "Chrome" : userAgent.includes("Safari/") ? "Safari" : "Browser";
  const os = userAgent.includes("iPhone") || userAgent.includes("iPad") ? "iOS" : userAgent.includes("Android") ? "Android" : userAgent.includes("Windows") ? "Windows" : userAgent.includes("Mac OS") ? "macOS" : userAgent.includes("Linux") ? "Linux" : "device";
  return `${browser} on ${os}`;
}

function formatSessionDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
