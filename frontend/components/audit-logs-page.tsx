"use client";

import { useEffect, useMemo, useState } from "react";
import type { AuditLog } from "../lib/types";
import { api } from "../lib/api";
import { Button, Card, CopyButton, ErrorBanner, InfoLink, Loading, PageHeader, Pagination, SortHeader, TableControls } from "./ui";
import { Icon } from "./icon";

export function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [filter, setFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("all");
  const [dateFilter, setDateFilter] = useState("all");
  const [showReadOnly, setShowReadOnly] = useState(false);
  const [sortKey, setSortKey] = useState<"action" | "actorType" | "createdAt">("createdAt");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = (next = page) => { setLoading(true); setError(""); api.auditLogs(next).then((result) => { setLogs(result.items); setPage(Math.min(Math.max(result.page, 0), Math.max(result.totalPages - 1, 0))); setTotalPages(Math.max(result.totalPages, 1)); }).catch((err) => setError(err.message)).finally(() => setLoading(false)); };
  useEffect(() => { load(0); }, [filter, actorFilter, dateFilter, showReadOnly]);

  const visible = useMemo(() => logs.filter((log) => {
    const query = `${formatAction(log.action)} ${log.actorType} ${log.actorAccountId ?? ""} ${log.ipAddress ?? ""}`.toLowerCase();
    const matchesDate = dateFilter === "all" || (dateFilter === "today" && new Date(log.createdAt).toDateString() === new Date().toDateString());
    return (showReadOnly || !isReadOnly(log.action)) && (actorFilter === "all" || log.actorType === actorFilter) && matchesDate && query.includes(filter.toLowerCase());
  }).sort((a, b) => compare(a[sortKey], b[sortKey], sortDirection)), [actorFilter, dateFilter, filter, logs, showReadOnly, sortDirection, sortKey]);
  const toggleSort = (key: typeof sortKey) => { if (sortKey === key) setSortDirection(sortDirection === "asc" ? "desc" : "asc"); else { setSortKey(key); setSortDirection("asc"); } };

  const filterActive = Boolean(filter || actorFilter !== "all" || dateFilter !== "all" || showReadOnly);
  const displayTotalPages = visible.length === 0 || filterActive ? 1 : totalPages;
  const clearFilters = () => { setFilter(""); setActorFilter("all"); setDateFilter("all"); setShowReadOnly(false); setPage(0); };
  const filterSummary = filterActive && <div className="filter-summary"><span>{visible.length} {visible.length === 1 ? "match" : "matches"}</span>{filter && <span className="filter-token">Search: {filter} <button aria-label="Remove search filter" onClick={() => setFilter("")} type="button">×</button></span>}{actorFilter !== "all" && <span className="filter-token">Actor: {actorLabel(actorFilter)} <button aria-label="Remove actor filter" onClick={() => setActorFilter("all")} type="button">×</button></span>}{dateFilter !== "all" && <span className="filter-token">Date: {dateFilter} <button aria-label="Remove date filter" onClick={() => setDateFilter("all")} type="button">×</button></span>}{showReadOnly && <span className="filter-token">Read-only <button aria-label="Remove read-only filter" onClick={() => setShowReadOnly(false)} type="button">×</button></span>}<button className="clear-filters" onClick={clearFilters} type="button">Clear filters</button></div>;
  return <><PageHeader title="Audit logs" titleAdornment={<span className="page-title-adornment"><Icon name="shield" size={15} /> Append-only</span>} description="An immutable record of platform and account activity." />{error && <ErrorBanner message={error} />}<Card><div className="table-heading"><div><div className="table-title"><h2>Activity history ({visible.length})</h2><InfoLink /><span className="result-count">Newest first</span></div><p>Platform and account activity, with read-only events hidden by default.</p></div></div><div className="toolbar audit-toolbar"><div className="audit-filters"><label className="inline-search"><Icon name="search" size={16} /><input aria-label="Filter activity" onChange={(e) => setFilter(e.target.value)} placeholder="Filter activity" value={filter} /></label><label aria-label="Filter by actor" className="select-filter"><select onChange={(e) => setActorFilter(e.target.value)} value={actorFilter}><option value="all">All actors</option><option value="SA">SA</option><option value="ACCOUNT">Account</option><option value="APP_USER">End user</option></select></label><label aria-label="Filter by date" className="select-filter"><select onChange={(e) => setDateFilter(e.target.value)} value={dateFilter}><option value="all">All dates</option><option value="today">Today</option></select></label><label className="audit-checkbox"><input checked={showReadOnly} onChange={(e) => setShowReadOnly(e.target.checked)} type="checkbox" /> Show read-only events</label></div><div className="table-toolbar-actions"><Pagination page={filterActive || visible.length === 0 ? 0 : page} totalPages={displayTotalPages} pageSize={50} onChange={load} /><TableControls tableId="audit-logs" /></div></div>{filterSummary}{loading ? <Loading label="Loading audit logs" /> : <div className="table-wrap"><table><thead><tr><th aria-sort={sortKey === "action" ? sortDirection === "asc" ? "ascending" : "descending" : "none"}><SortHeader label="Action" active={sortKey === "action"} direction={sortDirection} onClick={() => toggleSort("action")} /></th><th aria-sort={sortKey === "actorType" ? sortDirection === "asc" ? "ascending" : "descending" : "none"}><SortHeader label="Actor" active={sortKey === "actorType"} direction={sortDirection} onClick={() => toggleSort("actorType")} /></th><th aria-sort={sortKey === "createdAt" ? sortDirection === "asc" ? "ascending" : "descending" : "none"}><SortHeader label="Time" active={sortKey === "createdAt"} direction={sortDirection} onClick={() => toggleSort("createdAt")} /></th><th>Request ID</th><th>Source</th><th /></tr></thead><tbody>{visible.map((log) => <AuditRow expanded={expanded === log.id} log={log} onToggle={() => setExpanded(expanded === log.id ? null : log.id)} key={log.id} />)}{visible.length === 0 && <tr><td colSpan={6}><div className="table-empty"><strong>No activity found</strong><p>Try changing or clearing the filters.</p><Button onClick={clearFilters} type="button" variant="secondary">Clear filters</Button></div></td></tr>}</tbody></table></div>}</Card></>;
}

function AuditRow({ log, expanded, onToggle }: { log: AuditLog; expanded: boolean; onToggle: () => void }) {
  return <><tr><td><button className="action-toggle" onClick={onToggle} type="button"><Icon name={expanded ? "chevronDown" : "chevronRight"} size={14} /><span><strong>{formatAction(log.action)}</strong><small>#{log.id}</small></span></button></td><td><span className="role-pill role-sa">{actorLabel(log.actorType)}</span>{log.actorAccountId && <span className="table-secondary mono">{shortId(log.actorAccountId)}</span>}</td><td className="muted"><time dateTime={log.createdAt} title={new Date(log.createdAt).toLocaleString(undefined, { dateStyle: "full", timeStyle: "medium" })}>{relativeTime(log.createdAt)}</time></td><td>{log.requestId ? <span className="request-id"><span className="mono muted">{shortId(log.requestId)}</span><CopyButton value={log.requestId} /></span> : "—"}</td><td className="muted">{normalizeIp(log.ipAddress)}</td><td><button className="details-button" onClick={onToggle} type="button">Details</button></td></tr>{expanded && <tr className="audit-detail-row"><td colSpan={6}><div className="audit-details"><strong>Event details</strong><pre>{JSON.stringify(log.metadata ?? {}, null, 2)}</pre></div></td></tr>}</>;
}

function isReadOnly(action: string) { return /(^|_)(VIEW|LIST|GET|READ|ME)(_|$)/i.test(action); }
function formatAction(value: string) { return value.replaceAll("_", " ").toLowerCase().replace(/(^|\s)\S/g, (letter) => letter.toUpperCase()); }
function actorLabel(value: string) { return value === "SA" ? "SA" : formatAction(value); }
function shortId(value: string) { return value.length > 14 ? `${value.slice(0, 12)}…` : value; }
function normalizeIp(value: string | null) { return value === "0:0:0:0:0:0:0:1" || value === "0:0:0:0:0:0:0:1%0" ? "::1" : value ?? "—"; }
function relativeTime(value: string) { const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000); if (seconds < 60) return `${Math.max(seconds, 0)} seconds ago`; const minutes = Math.round(seconds / 60); if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`; const hours = Math.round(minutes / 60); if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`; return `${Math.round(hours / 24)} days ago`; }
function compare(left: unknown, right: unknown, direction: "asc" | "desc") { const a = String(left ?? "").toLowerCase(); const b = String(right ?? "").toLowerCase(); const result = a.localeCompare(b, undefined, { numeric: true }); return direction === "asc" ? result : -result; }
