"use client";

import { useEffect, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";
import { usePathname } from "next/navigation";
import { Icon } from "./icon";

export function Button({ variant = "primary", icon, children, className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "quiet" | "danger"; icon?: React.ComponentProps<typeof Icon>["name"] }) {
  return <button className={`button button-${variant} ${className}`} {...props}>{icon && <Icon name={icon} size={16} />}{children}</button>;
}

export function Field({ label, hint, className = "", ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  return <label className={`field ${className}`}><span className="field-label">{label}</span><input {...props} />{hint && <span className="field-hint">{hint}</span>}</label>;
}

export function SelectField({ label, children, className = "", ...props }: SelectHTMLAttributes<HTMLSelectElement> & { label: string; children: ReactNode }) {
  return <label className={`field ${className}`}><span className="field-label">{label}</span><select {...props}>{children}</select></label>;
}

export function Card({ children, className = "", ...props }: React.HTMLAttributes<HTMLElement>) {
  return <section className={`card ${className}`} {...props}>{children}</section>;
}

export function StatusBadge({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone = normalized === "active" || normalized === "verified" || normalized === "operational" || normalized === "protected" ? "success" : normalized === "suspended" || normalized === "blocked" || normalized === "pending" ? "warning" : normalized === "invited" ? "info" : "neutral";
  const label = value.toLowerCase().replace(/(^|[_\s-])\S/g, (letter) => letter.toUpperCase());
  return <span className={`status status-${tone}`}><span className="status-dot" />{label}</span>;
}

export function PageHeader({ eyebrow, title, browserTitle, description, actions, titleAdornment }: { eyebrow?: string; title: ReactNode; browserTitle?: string; description?: string; actions?: ReactNode; titleAdornment?: ReactNode }) {
  const titleRef = useRef<HTMLHeadingElement>(null);
  void eyebrow;
  useEffect(() => {
    const pageTitle = browserTitle?.trim() || titleRef.current?.textContent?.trim();
    document.title = pageTitle ? `${pageTitle} | Auth Platform` : "Auth Platform";
  }, [browserTitle, title]);
  return <div className="page-header"><div><h1 ref={titleRef}>{title}{titleAdornment}</h1>{description && <p>{description}</p>}</div>{actions && <div className="page-actions">{actions}</div>}</div>;
}

export function MetricCard({ label, value, detail, icon, accent = "blue" }: { label: string; value: string | number; detail?: string; icon: React.ComponentProps<typeof Icon>["name"]; accent?: string }) {
  return <div className={`metric-card metric-${accent}`}><div className="metric-top"><span className="metric-label">{label}</span><span className="metric-icon"><Icon name={icon} size={18} /></span></div><div className="metric-value">{value}</div>{detail && <div className="metric-detail">{detail}</div>}</div>;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return <div className="loading"><span className="spinner" />{label}</div>;
}

export function ErrorBanner({ message }: { message: string }) {
  return <div className="error-banner"><Icon name="warning" size={17} /><span>{message}</span></div>;
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return <div className="empty-state"><div className="empty-mark"><Icon name="apps" size={22} /></div><h3>{title}</h3><p>{description}</p></div>;
}

export function Pagination({ page, totalPages, pageSize = 20, ariaLabel, onChange }: { page: number; totalPages: number; pageSize?: number; ariaLabel?: string; onChange: (page: number) => void }) {
  if (totalPages <= 1) return null;
  const pages = Math.max(1, Math.floor(totalPages));
  const current = Math.min(Math.max(Math.floor(page), 0), pages - 1);
  const itemsPerPage = Math.max(1, Math.floor(pageSize));
  const windowSize = 5;
  let start = Math.max(1, current + 1 - Math.floor(windowSize / 2));
  let end = Math.min(pages, start + windowSize - 1);
  start = Math.max(1, end - windowSize + 1);
  const pageNumbers: Array<number | "ellipsis"> = [];

  if (start > 1) {
    pageNumbers.push(1);
    if (start > 2) pageNumbers.push("ellipsis");
  }
  for (let number = start; number <= end; number += 1) pageNumbers.push(number);
  if (end < pages) {
    if (end < pages - 1) pageNumbers.push("ellipsis");
    pageNumbers.push(pages);
  }

  return (
    <nav aria-label={ariaLabel ?? `Table pagination, ${itemsPerPage} items per page`} className="table-pagination">
      <button
        aria-label="Previous page"
        className="table-pagination-arrow"
        disabled={current === 0}
        onClick={() => onChange(current - 1)}
        type="button"
      >‹</button>
      <span className="table-pagination-pages">
        {pageNumbers.map((number, index) => number === "ellipsis"
          ? <span aria-hidden="true" className="table-pagination-ellipsis" key={`ellipsis-${index}`}>…</span>
          : <button
              aria-current={number === current + 1 ? "page" : undefined}
              aria-label={`Page ${number}`}
              className={`table-pagination-page${number === current + 1 ? " table-pagination-page-current" : ""}`}
              key={number}
              onClick={() => onChange(number - 1)}
              type="button"
            >{number}</button>)}
      </span>
      <button
        aria-label="Next page"
        className="table-pagination-arrow"
        disabled={current === pages - 1}
        onClick={() => onChange(current + 1)}
        type="button"
      >›</button>
    </nav>
  );
}

export function Toggle({ checked, onChange, label, disabled = false, loading = false }: { checked: boolean; onChange: (checked: boolean) => void; label: string; disabled?: boolean; loading?: boolean }) {
  return <button aria-checked={checked} aria-label={label} aria-busy={loading || undefined} className={`toggle ${checked ? "toggle-on" : ""}`} disabled={disabled || loading} onClick={() => onChange(!checked)} role="switch" type="button">{loading ? <span aria-hidden="true" className="toggle-spinner" /> : <span className="toggle-thumb" />}</button>;
}

export function InfoLink({ children = "Info" }: { children?: ReactNode }) {
  return <button className="info-link" type="button" title="More information">{children}</button>;
}

export function SortHeader({ label, active, direction, onClick }: { label: string; active?: boolean; direction?: "asc" | "desc"; onClick?: () => void }) {
  return <button aria-label={`Sort by ${label}`} aria-sort={active ? direction === "desc" ? "descending" : "ascending" : "none"} className={`sort-header ${active ? "sort-active" : ""}`} onClick={onClick} type="button">{label}<span aria-hidden="true">{active ? direction === "desc" ? "▼" : "▲" : "↕"}</span></button>;
}

export function TableControls({ children, tableId = "table" }: { children?: ReactNode; tableId?: string }) {
  return <div className="table-controls"><TablePreferences tableId={tableId} />{children}</div>;
}

type TablePreferenceState = { pageSize: number; wrapLines: boolean; visibleColumns: string[] };

export function TablePreferences({ tableId = "table", columns = [] }: { tableId?: string; columns?: string[] }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const storageKey = `authplatform.table-preferences.${tableId === "table" ? pathname : tableId}`;
  const columnOptions = columns.length > 0 ? columns : ["All columns"];
  const defaultState: TablePreferenceState = { pageSize: 20, wrapLines: false, visibleColumns: columnOptions };
  const [draft, setDraft] = useState<TablePreferenceState>(defaultState);
  const [saved, setSaved] = useState<TablePreferenceState>(defaultState);
  useEffect(() => {
    try {
      const parsed = window.localStorage.getItem(storageKey);
      if (parsed) { const next = { ...defaultState, ...JSON.parse(parsed) } as TablePreferenceState; setSaved(next); setDraft(next); }
    } catch { /* localStorage may be unavailable in private browsing. */ }
  }, [storageKey]);
  const close = () => { setDraft(saved); setOpen(false); };
  const confirm = () => { try { window.localStorage.setItem(storageKey, JSON.stringify(draft)); window.dispatchEvent(new Event("authplatform:table-preferences")); } catch { /* best effort */ } setSaved(draft); setOpen(false); };
  return <><button aria-label="Preferences" className="table-icon-button" onClick={() => setOpen(true)} type="button" title="Preferences"><Icon name="settings" size={20} /></button>{open && <div className="modal-backdrop"><div className="modal preferences-modal" role="dialog" aria-modal="true" aria-labelledby="preferences-title"><div className="modal-header"><div><h2 id="preferences-title">Preferences</h2><p>Choose how this table is displayed.</p></div><button aria-label="Close preferences" className="icon-button" onClick={close} type="button"><Icon name="close" /></button></div><div className="preference-list"><fieldset><legend>Page size</legend>{[10, 20, 50].map((size) => <label className="preference-option" key={size}><input checked={draft.pageSize === size} name={`${tableId}-page-size`} onChange={() => setDraft({ ...draft, pageSize: size })} type="radio" />{size} rows</label>)}</fieldset><label className="preference-option"><input checked={draft.wrapLines} onChange={(event) => setDraft({ ...draft, wrapLines: event.target.checked })} type="checkbox" /> Wrap lines</label><fieldset><legend>Visible columns</legend>{columnOptions.map((column) => <label className="preference-option" key={column}><input checked={draft.visibleColumns.includes(column)} onChange={(event) => setDraft({ ...draft, visibleColumns: event.target.checked ? [...draft.visibleColumns, column] : draft.visibleColumns.filter((item) => item !== column) })} type="checkbox" />{column}</label>)}</fieldset></div><div className="modal-actions"><Button onClick={close} type="button" variant="quiet">Cancel</Button><Button onClick={confirm} type="button">Confirm</Button></div></div></div>}</>;
}

export function Stack({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`stack ${className}`}>{children}</div>;
}

export function ConfirmModal({ title, description, resourceName, confirmLabel, onCancel, onConfirm, busy = false }: { title: string; description: string; resourceName: string; confirmLabel: string; onCancel: () => void; onConfirm: () => void; busy?: boolean }) {
  const [value, setValue] = useState("");
  return <div className="modal-backdrop"><div className="modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title"><div className="modal-header"><div><h2 id="confirm-title">{title}</h2><p>{description}</p></div><button aria-label="Close confirmation" className="icon-button" disabled={busy} onClick={onCancel} type="button"><Icon name="close" /></button></div><Field disabled={busy} label={`Type ${resourceName} to confirm`} onChange={(event) => setValue(event.target.value)} value={value} /><div className="modal-actions"><Button disabled={busy} onClick={onCancel} type="button" variant="quiet">Cancel</Button><Button disabled={value !== resourceName || busy} onClick={onConfirm} type="button" variant="danger">{busy ? "Working…" : confirmLabel}</Button></div></div></div>;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    const fallbackCopy = () => {
      const area = document.createElement("textarea");
      area.value = value;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.focus();
      area.select();
      document.execCommand("copy");
      area.remove();
    };

    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
      else fallbackCopy();
    } catch {
      try { fallbackCopy(); } catch { return; }
    }

    try {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };
  return <button className={`copy-button ${copied ? "copy-button-copied" : ""}`} title={copied ? "Copied" : label} type="button" onClick={copy}><Icon name={copied ? "activity" : "copy"} size={14} />{label !== "Copy" && (copied ? "Copied" : label)}</button>;
}
