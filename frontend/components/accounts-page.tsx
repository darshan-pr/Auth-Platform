"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { Account } from "../lib/types";
import { api } from "../lib/api";
import { Button, Card, ErrorBanner, Field, InfoLink, Loading, PageHeader, Pagination, SortHeader, StatusBadge, TableControls } from "./ui";
import { Icon } from "./icon";

const ACCOUNT_PAGE_SIZE = 10;

export function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([]); const [page, setPage] = useState(0); const [filter, setFilter] = useState(""); const [sortKey, setSortKey] = useState<"name" | "platformRole" | "status" | "appCount" | "createdAt">("name"); const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc"); const [showCreate, setShowCreate] = useState(false); const [error, setError] = useState(""); const [loading, setLoading] = useState(true);
  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const firstPage = await api.accounts(0, 100);
      const remainingPages = await Promise.all(
        Array.from({ length: Math.max(firstPage.totalPages - 1, 0) }, (_, index) =>
          api.accounts(index + 1, 100)
        )
      );
      setAccounts([firstPage, ...remainingPages].flatMap((result) => result.items));
      setPage(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load accounts.");
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void load(); }, []);
  const visible = useMemo(
    () => accounts.filter((item) => `${item.name} ${item.email} ${item.platformRole}`.toLowerCase().includes(filter.toLowerCase())).sort((a, b) => compare(a[sortKey], b[sortKey], sortDirection)),
    [accounts, filter, sortDirection, sortKey]
  );
  const totalPages = Math.ceil(visible.length / ACCOUNT_PAGE_SIZE);
  const visiblePage = visible.slice(page * ACCOUNT_PAGE_SIZE, (page + 1) * ACCOUNT_PAGE_SIZE);
  const toggleSort = (key: typeof sortKey) => { if (sortKey === key) setSortDirection(sortDirection === "asc" ? "desc" : "asc"); else { setSortKey(key); setSortDirection("asc"); } };
  return <><PageHeader title="Accounts" description="Developer and SA accounts with access to the platform." actions={<Button onClick={() => setShowCreate(true)}>Create SA account</Button>} />{error && <ErrorBanner message={error} />}{showCreate && <CreateSaForm onClose={() => setShowCreate(false)} onCreated={() => { setShowCreate(false); void load(); }} /> }<Card><div className="table-heading"><div><div className="table-title"><h2>Accounts ({filter ? visible.length : accounts.length})</h2><InfoLink /><span className="result-count">Platform accounts</span></div><p>Developer and SA accounts with access to the platform.</p></div></div><div className="toolbar accounts-toolbar"><label className="inline-search"><Icon name="search" size={16} /><input onChange={(event) => { setFilter(event.target.value); setPage(0); }} placeholder="Filter accounts" value={filter} /></label><div className="table-toolbar-actions"><Pagination page={page} totalPages={totalPages} pageSize={ACCOUNT_PAGE_SIZE} onChange={setPage} /><TableControls /></div></div>{loading ? <Loading label="Loading accounts" /> : <div className="table-wrap"><table><thead><tr><th><SortHeader label="Account" active={sortKey === "name"} direction={sortDirection} onClick={() => toggleSort("name")} /></th><th><SortHeader label="Role" active={sortKey === "platformRole"} direction={sortDirection} onClick={() => toggleSort("platformRole")} /></th><th><SortHeader label="Status" active={sortKey === "status"} direction={sortDirection} onClick={() => toggleSort("status")} /></th><th><SortHeader label="Applications" active={sortKey === "appCount"} direction={sortDirection} onClick={() => toggleSort("appCount")} /></th><th><SortHeader label="Created" active={sortKey === "createdAt"} direction={sortDirection} onClick={() => toggleSort("createdAt")} /></th></tr></thead><tbody>{visiblePage.map((account) => <tr key={account.id}><td><Link className="table-primary" href={`/accounts/${account.id}`}>{account.name}</Link><span className="table-secondary">{account.email}</span></td><td><span className={`role-pill role-${account.platformRole.toLowerCase()}`}>{account.platformRole === "SA" ? "SA" : "User"}</span></td><td><StatusBadge value={account.status} /></td><td>{account.appCount}</td><td className="muted">{formatDate(account.createdAt)}</td></tr>)}{visiblePage.length === 0 && <tr><td colSpan={5}><div className="table-empty">No accounts match this filter.</div></td></tr>}</tbody></table></div>}</Card></>;
}

function CreateSaForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ name: "", email: "", password: "" }); const [error, setError] = useState(""); const [saving, setSaving] = useState(false);
  const submit = async (event: React.FormEvent) => { event.preventDefault(); setSaving(true); setError(""); try { await api.createSa(form); onCreated(); } catch (err) { setError(err instanceof Error ? err.message : "Unable to create account"); } finally { setSaving(false); } };
  return <div className="modal-backdrop"><div className="modal"><div className="modal-header"><div><div className="eyebrow">NEW ACCOUNT</div><h2>Create SA account</h2></div><button className="icon-button" onClick={onClose}><Icon name="close" /></button></div>{error && <ErrorBanner message={error} />}<form onSubmit={submit}><div className="form-grid"><Field label="Full name" onChange={(event) => setForm({ ...form, name: event.target.value })} required value={form.name} /><Field label="Email address" onChange={(event) => setForm({ ...form, email: event.target.value })} required type="email" value={form.email} /><Field className="span-2" hint="At least 10 characters" label="Temporary password" onChange={(event) => setForm({ ...form, password: event.target.value })} required type="password" value={form.password} /></div><div className="modal-actions"><Button onClick={onClose} type="button" variant="quiet">Cancel</Button><Button disabled={saving} type="submit">{saving ? "Creating…" : "Create account"}</Button></div></form></div></div>;
}

function formatDate(value: string) { return new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(new Date(value)); }
function compare(left: unknown, right: unknown, direction: "asc" | "desc") { const a = String(left ?? "").toLowerCase(); const b = String(right ?? "").toLowerCase(); const result = a.localeCompare(b, undefined, { numeric: true }); return direction === "asc" ? result : -result; }
