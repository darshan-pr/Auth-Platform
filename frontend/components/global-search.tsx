"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, consoleApi } from "../lib/api";
import type { SearchHit, SearchResponse, SearchType } from "../lib/types";
import { Icon } from "./icon";

type Scope = "sa" | "console";
type NavItem = { href: string; label: string };
type Row = { key: string; group: string; title: string; subtitle?: string; badge?: string; href: string; icon: "apps" | "users" | "audit" | "shield" | "grid" };

const MIN_QUERY = 2;
const DEBOUNCE_MS = 250;
const groupLabels: Record<SearchType, string> = {
  ACCOUNT: "Accounts",
  APPLICATION: "Applications",
  END_USER: "End users",
  AUDIT_EVENT: "Audit events",
};

function hitHref(scope: Scope, hit: SearchHit): string {
  if (hit.type === "ACCOUNT") return `/accounts/${hit.id}`;
  if (hit.type === "APPLICATION") return scope === "console" ? `/console/apps/${hit.id}` : `/apps/${hit.id}`;
  if (hit.type === "END_USER") {
    if (scope === "console") return `/console/apps/${hit.appId}/users/${hit.id}`;
    return `/users?${new URLSearchParams({ appId: hit.appId ?? "", q: hit.subtitle ?? hit.title })}`;
  }
  return `/audit-logs?${new URLSearchParams({ q: hit.title })}`;
}

function hitRow(scope: Scope, hit: SearchHit): Row {
  const label = hit.type === "AUDIT_EVENT" ? hit.title.replaceAll("_", " ").toLowerCase().replace(/(^|\s)\S/g, (letter) => letter.toUpperCase()) : hit.title;
  const subtitle = hit.type === "END_USER" ? [hit.subtitle, hit.appName].filter(Boolean).join(" · ") : hit.subtitle ?? undefined;
  return {
    key: `${hit.type}:${hit.id}`,
    group: groupLabels[hit.type],
    title: label,
    subtitle,
    badge: hit.status && hit.status !== "ACTIVE" ? hit.status.toLowerCase() : undefined,
    href: hitHref(scope, hit),
    icon: hit.type === "APPLICATION" ? "apps" : hit.type === "AUDIT_EVENT" ? "audit" : hit.type === "ACCOUNT" ? "shield" : "users",
  };
}

/** The ⌘K / Ctrl+K command palette: page shortcuts plus server-side search of resources. */
export function GlobalSearch({ scope, nav }: { scope: Scope; nav: NavItem[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [response, setResponse] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [active, setActive] = useState(0);
  const trigger = useRef<HTMLButtonElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const query = text.trim();
  const searching = query.length >= MIN_QUERY;

  const close = useCallback(() => { setOpen(false); setText(""); setResponse(null); setError(""); setActive(0); trigger.current?.focus(); }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const typing = event.target instanceof HTMLElement && (event.target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(event.target.tagName));
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setOpen((value) => !value); }
      else if (event.key === "/" && !typing && !event.metaKey && !event.ctrlKey && !event.altKey) { event.preventDefault(); setOpen(true); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => { if (open) input.current?.focus(); }, [open]);

  // Debounced search; a newer keystroke cancels the request still in flight.
  useEffect(() => {
    if (!open || !searching) { setResponse(null); setLoading(false); setError(""); return; }
    const controller = new AbortController();
    setLoading(true);
    const timer = window.setTimeout(() => {
      (scope === "console" ? consoleApi : api).search(query, controller.signal)
        .then((result) => { setResponse(result); setError(""); setActive(0); })
        .catch((err) => { if (!controller.signal.aborted) { setResponse(null); setError(err instanceof Error ? err.message : "Search failed"); } })
        .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    }, DEBOUNCE_MS);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [open, query, scope, searching]);

  const rows = useMemo<Row[]>(() => {
    const needle = query.toLowerCase();
    const pages: Row[] = nav
      .filter((item) => !needle || item.label.toLowerCase().includes(needle))
      .map((item) => ({ key: `page:${item.href}`, group: "Pages", title: item.label, href: item.href, icon: "grid" as const }));
    const found = (response?.groups ?? []).flatMap((group) => group.items.map((hit) => hitRow(scope, hit)));
    return searching ? [...found, ...pages] : pages;
  }, [nav, query, response, scope, searching]);

  useEffect(() => { setActive((current) => Math.min(current, Math.max(rows.length - 1, 0))); }, [rows.length]);
  useEffect(() => { list.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" }); }, [active]);

  const go = (row: Row) => { close(); router.push(row.href); };
  const onInputKey = (event: React.KeyboardEvent) => {
    if (event.key === "ArrowDown") { event.preventDefault(); setActive((value) => (rows.length ? (value + 1) % rows.length : 0)); }
    else if (event.key === "ArrowUp") { event.preventDefault(); setActive((value) => (rows.length ? (value - 1 + rows.length) % rows.length : 0)); }
    else if (event.key === "Enter" && rows[active]) { event.preventDefault(); go(rows[active]); }
    else if (event.key === "Escape") { event.preventDefault(); close(); }
  };

  const grouped: { group: string; items: { row: Row; index: number }[] }[] = [];
  rows.forEach((row, index) => {
    const last = grouped[grouped.length - 1];
    if (last && last.group === row.group) last.items.push({ row, index });
    else grouped.push({ group: row.group, items: [{ row, index }] });
  });
  const truncated = response?.groups.filter((group) => group.hasMore).map((group) => groupLabels[group.type].toLowerCase()) ?? [];

  return <>
    <button aria-haspopup="dialog" aria-label="Search resources" className="global-search" onClick={() => setOpen(true)} ref={trigger} type="button"><Icon name="search" size={17} /><span>Search resources</span><kbd>⌘ K</kbd></button>
    {open && <div className="search-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) close(); }}>
      <div aria-label="Search" aria-modal="true" className="search-palette" role="dialog">
        <div className="search-input-row">
          <Icon name="search" size={18} />
          <input aria-activedescendant={rows[active] ? `search-option-${active}` : undefined} aria-autocomplete="list" aria-controls="search-results" aria-expanded="true" autoComplete="off" maxLength={100} onChange={(event) => setText(event.target.value)} onKeyDown={onInputKey} placeholder={scope === "console" ? "Search applications and end users" : "Search accounts, applications, end users and events"} ref={input} role="combobox" spellCheck={false} value={text} />
          {loading && <span aria-label="Searching" className="search-spinner" role="status" />}
          <kbd>esc</kbd>
        </div>
        <div className="search-results" id="search-results" ref={list} role="listbox">
          {error && <p className="search-message search-error" role="alert">{error}</p>}
          {!error && query.length > 0 && !searching && <p className="search-message">Type at least {MIN_QUERY} characters to search.</p>}
          {!error && searching && !loading && response && response.groups.length === 0 && <p className="search-message">No results for “{query}”.</p>}
          {grouped.map(({ group, items }) => <div className="search-group" key={group} role="presentation">
            <div className="search-group-label">{group}</div>
            {items.map(({ row, index }) => <button aria-selected={index === active} className={`search-option ${index === active ? "search-option-active" : ""}`} data-index={index} id={`search-option-${index}`} key={row.key} onClick={() => go(row)} onMouseMove={() => setActive(index)} role="option" type="button">
              <span className="search-option-icon"><Icon name={row.icon} size={16} /></span>
              <span className="search-option-text"><strong>{row.title}</strong>{row.subtitle && <small>{row.subtitle}</small>}</span>
              {row.badge && <span className="search-badge">{row.badge}</span>}
            </button>)}
          </div>)}
          {truncated.length > 0 && <p className="search-message">Showing the closest matches for {truncated.join(", ")}. Add more of the name or email to narrow it down.</p>}
        </div>
        <div className="search-footer"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></div>
      </div>
    </div>}
  </>;
}
