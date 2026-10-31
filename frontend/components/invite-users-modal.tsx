"use client";

import { useEffect, useMemo, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { consoleApi } from "../lib/api";
import { INVITE_CHUNK_SIZE, MAX_IMPORT_ROWS, chunk, parseInvitees, stageInvitees, type StagedInvitee } from "../lib/invite-parser";
import type { InviteResult } from "../lib/types";
import { Button, ErrorBanner, Field } from "./ui";
import { Icon } from "./icon";

type Tab = "paste" | "csv" | "single";
type Totals = { invited: number; alreadyExists: number; duplicate: number; invalid: number };

const MAX_FILE_BYTES = 1_000_000;
const emptyTotals: Totals = { invited: 0, alreadyExists: 0, duplicate: 0, invalid: 0 };

export function InviteUsersModal({ appId, appName, onClose, onInvited }: { appId: string; appName: string; onClose: () => void; onInvited: () => void }) {
  const [tab, setTab] = useState<Tab>("paste");
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [staged, setStaged] = useState<StagedInvitee[]>([]);
  const [sending, setSending] = useState(false);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [totals, setTotals] = useState<Totals>(emptyTotals);
  const [issues, setIssues] = useState<InviteResult[]>([]);
  const [attempted, setAttempted] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const firstField = useRef<HTMLTextAreaElement>(null);
  const sendingRef = useRef(false);

  const ready = useMemo(() => staged.filter((row) => !row.error), [staged]);
  const needsAttention = staged.length - ready.length;
  const finished = attempted && !sending && ready.length === 0 && !error;

  useEffect(() => { firstField.current?.focus(); }, []);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape" && !sendingRef.current) close(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const close = () => {
    if (totals.invited > 0) onInvited();
    onClose();
  };

  const addRows = (rows: { email: string; name: string }[]) => {
    setError("");
    setNotice("");
    if (rows.length === 0) { setNotice("No email addresses were found."); return; }
    if (staged.length + rows.length > MAX_IMPORT_ROWS) { setError(`You can stage at most ${MAX_IMPORT_ROWS} users at a time.`); return; }
    const added = stageInvitees(rows, staged);
    setStaged([...staged, ...added]);
    const skipped = added.filter((row) => row.error).length;
    setNotice(`Added ${added.length - skipped} ${added.length - skipped === 1 ? "person" : "people"}${skipped ? `; ${skipped} need attention` : ""}.`);
  };

  const addPasted = () => { addRows(parseInvitees(text)); setText(""); };
  const addSingle = (event: FormEvent) => { event.preventDefault(); addRows([{ email, name: name.trim() }]); setEmail(""); setName(""); };
  const addFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) { setError("That file is larger than 1 MB. Split it into smaller files."); return; }
    try { addRows(parseInvitees(await file.text())); } catch { setError("We couldn't read that file."); }
  };

  const send = async () => {
    const queue = ready;
    if (queue.length === 0 || sendingRef.current) return;
    sendingRef.current = true;
    setSending(true);
    setAttempted(true);
    setError("");
    setNotice("");
    setProgress({ done: 0, total: queue.length });
    let done = 0;
    for (const group of chunk(queue, INVITE_CHUNK_SIZE)) {
      try {
        const result = await consoleApi.inviteUsers(appId, group.map((row) => ({ email: row.email, name: row.name || undefined })));
        setTotals((current) => result.results.reduce((next, item) => ({
          invited: next.invited + (item.outcome === "INVITED" ? 1 : 0),
          alreadyExists: next.alreadyExists + (item.outcome === "ALREADY_EXISTS" ? 1 : 0),
          duplicate: next.duplicate + (item.outcome === "DUPLICATE" ? 1 : 0),
          invalid: next.invalid + (item.outcome === "INVALID" ? 1 : 0),
        }), current));
        setIssues((current) => [...current, ...result.results.filter((item) => item.outcome !== "INVITED")]);
        const sent = new Set(group.map((row) => row.key));
        setStaged((current) => current.filter((row) => !sent.has(row.key)));
        done += group.length;
        setProgress({ done, total: queue.length });
      } catch (err) {
        setError(`${err instanceof Error ? err.message : "Unable to send invitations."} ${done} of ${queue.length} were sent; the rest are still in the list so you can try again.`);
        break;
      }
    }
    sendingRef.current = false;
    setSending(false);
  };

  const removeRow = (key: string) => setStaged((current) => current.filter((row) => row.key !== key));
  const percent = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;

  return <div className="modal-backdrop"><div aria-labelledby="invite-title" aria-modal="true" className="modal invite-modal" role="dialog">
    <div className="modal-header"><div><div className="eyebrow">END USERS</div><h2 id="invite-title">Invite users to {appName}</h2><p>Each person gets one email with a temporary password and a link to verify their address. They show as Invited until they first sign in.</p></div><button aria-label="Close" className="icon-button" disabled={sending} onClick={close} type="button"><Icon name="close" /></button></div>
    {error && <ErrorBanner message={error} />}
    {finished ? <div className="invite-result">
      <div className="success-panel"><span className="success-icon">✓</span><strong>{totals.invited} {totals.invited === 1 ? "invitation" : "invitations"} sent</strong><p>{totals.alreadyExists + totals.duplicate + totals.invalid > 0 ? `${totals.alreadyExists} already had an account, ${totals.duplicate} duplicates, ${totals.invalid} invalid.` : "Everyone on the list was invited."}{needsAttention > 0 ? ` ${needsAttention} ${needsAttention === 1 ? "entry was" : "entries were"} skipped because they were not valid email addresses.` : ""}</p></div>
      {issues.length > 0 && <div className="invite-issues"><strong>Not invited</strong><ul>{issues.map((item, index) => <li key={`${item.email}-${index}`}><span className="mono">{item.email}</span><span className="muted">{item.message}</span></li>)}</ul></div>}
      <div className="modal-actions"><Button onClick={close} type="button">Done</Button></div>
    </div> : <>
      <nav aria-label="How to add people" className="tabs invite-tabs" role="tablist">
        {([["paste", "Paste emails"], ["csv", "Upload CSV"], ["single", "One by one"]] as [Tab, string][]).map(([key, label]) => <button aria-selected={tab === key} className={tab === key ? "tab-active" : ""} disabled={sending} key={key} onClick={() => { setTab(key); setError(""); setNotice(""); }} role="tab" type="button">{label}</button>)}
      </nav>
      {tab === "paste" && <div className="invite-input"><label className="field"><span className="field-label">Email addresses</span><textarea disabled={sending} onChange={(event) => setText(event.target.value)} placeholder={"ada@example.com\nGrace Hopper <grace@example.com>\nlin@example.com, kim@example.com"} ref={firstField} rows={5} value={text} /><span className="field-hint">One per line, or separated by commas, semicolons or spaces. “Name &lt;email&gt;” is supported.</span></label><div className="form-actions"><Button disabled={sending || !text.trim()} onClick={addPasted} type="button" variant="secondary">Add to list</Button></div></div>}
      {tab === "csv" && <div className="invite-input"><label className="invite-drop"><Icon name="mail" size={22} /><strong>Choose a CSV file</strong><span>Columns: <code>email</code> and optional <code>name</code>. Up to 1 MB.</span><input accept=".csv,.txt,text/csv,text/plain" disabled={sending} onChange={addFile} type="file" /></label></div>}
      {tab === "single" && <form className="invite-input invite-single" onSubmit={addSingle}><Field autoComplete="off" disabled={sending} label="Name (optional)" onChange={(event) => setName(event.target.value)} placeholder="Ada Lovelace" value={name} /><Field autoComplete="off" disabled={sending} label="Email address" onChange={(event) => setEmail(event.target.value)} placeholder="ada@example.com" required type="email" value={email} /><Button disabled={sending || !email.trim()} type="submit" variant="secondary">Add to list</Button></form>}
      {notice && <p className="invite-notice" role="status">{notice}</p>}
      <div className="invite-staged">
        <div className="invite-staged-head"><strong>{ready.length} ready{needsAttention > 0 ? ` · ${needsAttention} need attention` : ""}</strong>{staged.length > 0 && <button className="auth-text-button" disabled={sending} onClick={() => setStaged([])} type="button">Clear all</button>}</div>
        {staged.length === 0 ? <p className="invite-empty">People you add appear here before anything is sent.</p> : <ul>{staged.map((row) => <li className={row.error ? "invite-row-error" : ""} key={row.key}><span><strong>{row.name || row.email}</strong>{row.name && <small>{row.email}</small>}{row.error && <small className="invite-error-text">{row.error === "invalid" ? "Not a valid email address" : "Already in the list"}</small>}</span><button aria-label={`Remove ${row.email}`} className="table-icon-button" disabled={sending} onClick={() => removeRow(row.key)} type="button"><Icon name="close" size={14} /></button></li>)}</ul>}
      </div>
      {sending && <div aria-label="Sending invitations" aria-valuemax={100} aria-valuemin={0} aria-valuenow={percent} className="invite-progress" role="progressbar"><span style={{ width: `${percent}%` }} /><em>Sending {progress.done} of {progress.total}…</em></div>}
      {attempted && !sending && (totals.invited > 0 || issues.length > 0) && ready.length > 0 && <p className="invite-notice" role="status">{totals.invited} sent so far.</p>}
      <div className="modal-actions"><Button disabled={sending} onClick={close} type="button" variant="quiet">{totals.invited > 0 ? "Close" : "Cancel"}</Button><Button disabled={sending || ready.length === 0} onClick={send} type="button">{sending ? "Sending…" : error && attempted ? `Retry ${ready.length} remaining` : `Send ${ready.length || ""} ${ready.length === 1 ? "invitation" : "invitations"}`}</Button></div>
    </>}
  </div></div>;
}
