"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import type { AccountDetails as AccountDetailsData } from "../lib/types";
import { api } from "../lib/api";
import { Button, Card, ErrorBanner, Field, Loading, PageHeader } from "./ui";
import { AccountDetails } from "./account-details";

export function AccountDetailPage() {
  const { id } = useParams<{ id: string }>(); const router = useRouter(); const [data, setData] = useState<AccountDetailsData | null>(null); const [error, setError] = useState(""); const [editing, setEditing] = useState(false); const [saving, setSaving] = useState(false);
  const load = () => api.account(id).then(setData).catch((err) => setError(err.message)); useEffect(() => { load(); }, [id]);
  if (error) return <><Button variant="quiet" onClick={() => router.push("/accounts")}>Accounts</Button><ErrorBanner message={error} /></>;
  if (!data) return <Loading label="Loading account" />;
  const { account, apps } = data;
  return <><PageHeader title={account.name} description={account.email} />{editing ? <AccountEditor account={account} saving={saving} setSaving={setSaving} onCancel={() => setEditing(false)} onSaved={() => { setEditing(false); load(); }} /> : <><div className="account-details-actions"><Button variant="secondary" onClick={() => setEditing(true)}>Edit account</Button></div><AccountDetails account={account} apps={apps} showApplications /></>}</>;
}

function AccountEditor({ account, saving, setSaving, onCancel, onSaved }: { account: AccountDetailsData["account"]; saving: boolean; setSaving: (value: boolean) => void; onCancel: () => void; onSaved: () => void }) {
  const [name, setName] = useState(account.name); const [status, setStatus] = useState(account.status); const [role, setRole] = useState(account.platformRole); const [password, setPassword] = useState(""); const [error, setError] = useState("");
  const submit = async (event: React.FormEvent) => { event.preventDefault(); setSaving(true); setError(""); const payload: Record<string, unknown> = { name: name.trim(), status, platformRole: role }; if (password) payload.password = password; try { await api.updateAccount(account.id, payload); onSaved(); } catch (err) { setError(err instanceof Error ? err.message : "Unable to update account"); } finally { setSaving(false); } };
  return <Card className="editor-card"><div className="card-heading"><div><h2>Edit account</h2><p>Changes are recorded in the audit trail.</p></div></div>{error && <ErrorBanner message={error} />}<form onSubmit={submit}><div className="form-grid"><Field label="Full name" maxLength={120} onChange={(e) => setName(e.target.value)} required value={name} /><label className="field"><span className="field-label">Status</span><select onChange={(e) => setStatus(e.target.value)} value={status}><option>ACTIVE</option><option>SUSPENDED</option><option>BLOCKED</option></select></label><label className="field"><span className="field-label">Role</span><select onChange={(e) => setRole(e.target.value as typeof role)} value={role}><option value="USER">USER</option><option value="SA">SA</option></select></label><Field hint="Leave blank to keep the current password" label="New password" maxLength={128} minLength={10} onChange={(e) => setPassword(e.target.value)} type="password" value={password} /></div><div className="form-actions"><Button disabled={saving} onClick={onCancel} type="button" variant="secondary">Cancel</Button><Button disabled={saving || !name.trim()} type="submit">{saving ? "Saving…" : "Save changes"}</Button></div></form></Card>;
}
