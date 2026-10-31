"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ApiError, api, consoleApi } from "../lib/api";
import type { SessionInfo } from "../lib/types";
import { Icon } from "./icon";
import { SessionDialog } from "./session-dialog";

const saNav = [
  { href: "/overview", label: "Overview" },
  { href: "/accounts", label: "Accounts" },
  { href: "/apps", label: "Applications" },
  { href: "/users", label: "End users" },
  { href: "/audit-logs", label: "Audit logs" },
  { href: "/account", label: "Account" },
];

const developerNav = [
  { href: "/console/overview", label: "Overview" },
  { href: "/console/apps", label: "Applications" },
  { href: "/console/account", label: "Account" },
];

const displayName = "Darshan PR";
const displayParts = displayName.split(/\s+/).filter(Boolean);
const displayInitials = (displayParts.length > 1 ? displayParts.slice(0, 2).map((part) => part[0]).join("") : displayParts[0].slice(0, 2)).toUpperCase();

export function ConsoleShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const isConsole = pathname.startsWith("/console");
  const currentNav = isConsole ? developerNav : saNav;
  const [mobileNav, setMobileNav] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [accountMenu, setAccountMenu] = useState(false);
  const [sectionsOpen, setSectionsOpen] = useState(true);
  const [resourcesOpen, setResourcesOpen] = useState(true);
  const [authChecking, setAuthChecking] = useState(true);
  const [authCheckError, setAuthCheckError] = useState("");
  const [resourceLabel, setResourceLabel] = useState("");
  const [parentResourceLabel, setParentResourceLabel] = useState("");
  const [sessionDialogOpen, setSessionDialogOpen] = useState(false);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [sessionError, setSessionError] = useState("");
  const [sessionPendingId, setSessionPendingId] = useState("");
  const [signingOut, setSigningOut] = useState(false);

  const checkAuth = useCallback(async () => {
    setAuthChecking(true);
    setAuthCheckError("");
    try {
      if (isConsole) await consoleApi.me();
      else await api.analytics();
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        router.replace(isConsole ? "/login" : "/sa/login");
      } else {
        setAuthCheckError(error instanceof Error ? error.message : "The request could not be completed.");
      }
    } finally {
      setAuthChecking(false);
    }
  }, [isConsole, router]);

  useEffect(() => {
    void checkAuth();
  }, [checkAuth]);

  useEffect(() => {
    const userMatch = pathname.match(/^\/console\/apps\/([^/]+)\/users\/([^/]+)$/);
    const appMatch = pathname.match(/^\/(console\/)?apps\/([^/]+)$/);
    const accountMatch = pathname.match(/^\/accounts\/([^/]+)$/);
    setResourceLabel(""); setParentResourceLabel("");
    if (userMatch) {
      Promise.all([consoleApi.app(userMatch[1]), consoleApi.appUserDetails(userMatch[1], userMatch[2])]).then(([app, user]) => { setParentResourceLabel(app.name); setResourceLabel(user.user.name); }).catch(() => undefined);
    } else if (appMatch) {
      const request = isConsole ? consoleApi.app(appMatch[2]) : api.app(appMatch[2]);
      request.then((app) => setResourceLabel(app.name)).catch(() => undefined);
    } else if (accountMatch) {
      api.account(accountMatch[1]).then((result) => setResourceLabel(result.account.name)).catch(() => undefined);
    }
  }, [isConsole, pathname]);

  const currentLabel = currentNav.find((item) => pathname === item.href || pathname.startsWith(`${item.href}/`))?.label ?? "Console";
  const completeSignOut = async () => {
    setSigningOut(true);
    setSessionError("");
    try {
      if (isConsole) await consoleApi.logout();
      else await api.logout();
      setSessionDialogOpen(false);
      router.replace(isConsole ? "/login" : "/sa/login");
    } catch (err) {
      setSessionError(err instanceof Error ? err.message : "Unable to sign out.");
    } finally {
      setSigningOut(false);
    }
  };

  const signOut = async () => {
    setSessionError("");
    try {
      const activeSessions = isConsole ? await consoleApi.sessions() : await api.sessions();
      setSessions(activeSessions);
      if (activeSessions.some((session) => !session.current)) {
        setSessionDialogOpen(true);
        return;
      }
      await completeSignOut();
    } catch (err) {
      setSessions([]);
      setSessionError(err instanceof Error ? err.message : "Unable to load active sessions.");
      setSessionDialogOpen(true);
    }
  };

  const revokeSession = async (session: SessionInfo) => {
    setSessionPendingId(session.id);
    setSessionError("");
    try {
      if (isConsole) await consoleApi.revokeSession(session.id);
      else await api.revokeSession(session.id);
      setSessions((current) => current.filter((item) => item.id !== session.id));
    } catch (err) {
      setSessionError(err instanceof Error ? err.message : "Unable to revoke this session.");
    } finally {
      setSessionPendingId("");
    }
  };

  if (authChecking) return <div className="shell-loading">Loading console…</div>;
  if (authCheckError) return <div className="shell-loading" role="alert"><div><p>We couldn't verify your session. It has not been cleared.</p><p>{authCheckError}</p><button className="button button-secondary" onClick={() => void checkAuth()} type="button">Retry</button></div></div>;

  return <div className="console-frame">
    <header className="topbar">
      <div className="brand"><img alt="" className="brand-logo" src="/auth-platform-icon-white.png" /><span>Auth<span className="brand-accent"> Platform</span></span></div>
      <div className="global-search"><Icon name="search" size={17} /><span>Search resources</span><kbd>⌘ K</kbd></div>
      <div className="topbar-tools"><div className="account-wrap"><button aria-label={`Account menu for ${displayName}`} className="account-trigger" onClick={() => setAccountMenu(!accountMenu)} title={displayName} type="button"><span aria-hidden="true" className="account-avatar">{displayInitials}</span><span className="account-display-name">{displayName}</span></button>{accountMenu && <div className="account-menu"><div className="account-menu-name">{displayName}</div><div className="account-menu-role">darshanpr26@gmail.com</div><div className="account-menu-role">{isConsole ? "Developer workspace" : "Platform administration"}</div><Link className="account-menu-link" href={isConsole ? "/console/account" : "/account"} onClick={() => setAccountMenu(false)}>Account</Link><button onClick={signOut} type="button">Sign out</button></div>}</div></div>
    </header>
    <div className="contextbar">
      <button className="mobile-menu" onClick={() => setMobileNav(!mobileNav)} type="button"><Icon name="menu" size={21} /></button>
      <Link href={isConsole ? "/console/overview" : "/overview"} className="context-product">Auth Platform</Link><Icon name="chevronRight" size={16} />
      {parentResourceLabel ? <><Link href="/console/apps" className="context-product">Applications</Link><Icon name="chevronRight" size={16} /><Link href={pathname.replace(/\/users\/[^/]+$/, "")} className="context-product">{parentResourceLabel}</Link><Icon name="chevronRight" size={16} /><span className="context-current">{resourceLabel}</span></> : resourceLabel ? <><Link href={isConsole ? "/console/apps" : pathname.startsWith("/accounts/") ? "/accounts" : "/apps"} className="context-product">{currentLabel}</Link><Icon name="chevronRight" size={16} /><span className="context-current">{resourceLabel}</span></> : <span className="context-current">{currentLabel}</span>}
      <span className="context-spacer" /><span className="context-info" title="Console information">ⓘ</span>
    </div>
    {sessionDialogOpen && <SessionDialog error={sessionError} onCancel={() => setSessionDialogOpen(false)} onRevoke={revokeSession} onSignOut={completeSignOut} pendingId={sessionPendingId} sessions={sessions} signingOut={signingOut} />}
    <div className="work-area">
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""} ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
        <div className="sidebar-heading-row"><div className="sidebar-heading">{isConsole ? "Developer workspace" : "Platform administration"}</div><button className="sidebar-collapse" onClick={() => setSidebarCollapsed(!sidebarCollapsed)} type="button" title="Collapse navigation"><Icon name="chevronRight" size={16} /></button></div>
        {!sidebarCollapsed && <>
          <button className={`sidebar-section-label sidebar-section-toggle ${sectionsOpen ? "section-open" : ""}`} onClick={() => setSectionsOpen(!sectionsOpen)} type="button"><span>{isConsole ? "Workspace" : "Console"}</span></button>
          {sectionsOpen && currentNav.map((item) => <Link key={item.href} href={item.href} className={`nav-item ${pathname === item.href || pathname.startsWith(`${item.href}/`) ? "nav-active" : ""}`} onClick={() => setMobileNav(false)}>{item.label}</Link>)}
          <div className="sidebar-rule" />
          <button className={`sidebar-section-label sidebar-section-toggle ${resourcesOpen ? "section-open" : ""}`} onClick={() => setResourcesOpen(!resourcesOpen)} type="button"><span>Resources</span></button>
          {resourcesOpen && <><a className="nav-item" href="/docs" rel="noreferrer" target="_blank">Documentation <Icon name="external" size={13} /></a><a className="nav-item" href="http://localhost:8080/swagger-ui/index.html" rel="noreferrer" target="_blank">API reference <Icon name="external" size={13} /></a>{!isConsole && <Link className="nav-item" href="/console/overview">Developer console <Icon name="chevronRight" size={13} /></Link>}</>}
          <div className="sidebar-bottom"><div className="sa-chip"><span className="avatar avatar-small">D</span><div><strong>{isConsole ? "Developer session" : "SA session"}</strong><span>Authenticated</span></div><span className="online-dot" /></div></div>
        </>}
      </aside>
      <main className="main-content">{children}</main>
    </div>
  </div>;
}
