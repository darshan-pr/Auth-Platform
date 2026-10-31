export type ParsedInvitee = { email: string; name: string };

export const MAX_IMPORT_ROWS = 5000;
export const INVITE_CHUNK_SIZE = 50;

const EMAIL = /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]+$/;
const EMAIL_HEADER = /^(e-?mail|e-?mail address|email_address|address)$/i;
const NAME_HEADER = /^(name|full[ _-]?name|display[ _-]?name|first[ _-]?name)$/i;

export function isValidEmail(value: string): boolean {
  return value.length <= 320 && EMAIL.test(value);
}

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

// Splits one CSV line on commas, semicolons or tabs, honouring double quotes.
function splitCells(line: string): string[] {
  const cells: string[] = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quoted) {
      if (char === '"' && line[index + 1] === '"') { current += '"'; index += 1; }
      else if (char === '"') quoted = false;
      else current += char;
    } else if (char === '"') quoted = true;
    else if (char === "," || char === ";" || char === "\t") { cells.push(current); current = ""; }
    else current += char;
  }
  cells.push(current);
  return cells.map((cell) => cell.trim());
}

function cleanName(value: string): string {
  return value.replace(/^["']+|["']+$/g, "").replace(/\s+/g, " ").trim();
}

/**
 * Reads pasted text or CSV content into invitees. Accepts one address per line, comma/semicolon/
 * space separated lists, "Name <email>" and CSV with or without an `email`/`name` header row.
 * Rows that do not look like an email are kept (with the raw text) so the user can see and fix them.
 */
export function parseInvitees(text: string): ParsedInvitee[] {
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const rows: ParsedInvitee[] = [];
  let emailColumn = -1;
  let nameColumn = -1;

  lines.forEach((line, lineIndex) => {
    const angle = /^(.*?)<\s*([^<>\s]+@[^<>\s]+)\s*>\s*$/.exec(line);
    if (angle) {
      rows.push({ email: angle[2], name: cleanName(angle[1]) });
      return;
    }
    const cells = splitCells(line);
    if (lineIndex === 0 && !cells.some((cell) => cell.includes("@"))) {
      const email = cells.findIndex((cell) => EMAIL_HEADER.test(cell));
      if (email >= 0) {
        emailColumn = email;
        nameColumn = cells.findIndex((cell) => NAME_HEADER.test(cell));
        return;
      }
    }
    if (emailColumn >= 0 && cells.length > emailColumn) {
      rows.push({ email: cells[emailColumn], name: nameColumn >= 0 ? cleanName(cells[nameColumn] ?? "") : "" });
      return;
    }
    const expanded = cells.flatMap((cell) => (cell.includes("@") && /\s/.test(cell) ? cell.split(/\s+/) : [cell]));
    const emailCells = expanded.filter((cell) => cell.includes("@"));
    if (emailCells.length >= 2) {
      emailCells.forEach((email) => rows.push({ email, name: "" }));
    } else if (emailCells.length === 1) {
      const name = expanded.find((cell) => cell && cell !== emailCells[0]) ?? "";
      rows.push({ email: emailCells[0], name: cleanName(name) });
    } else {
      rows.push({ email: line, name: "" });
    }
  });
  return rows;
}

export type StagedInvitee = { key: string; email: string; name: string; error?: "invalid" | "duplicate" };

/** Flags invalid and duplicate addresses; the first occurrence of an address wins. */
export function stageInvitees(rows: ParsedInvitee[], existing: StagedInvitee[] = []): StagedInvitee[] {
  const seen = new Set(existing.filter((row) => row.error !== "invalid").map((row) => normalizeEmail(row.email)));
  return rows.map((row, index) => {
    const email = row.email.trim();
    const key = `${Date.now().toString(36)}-${existing.length + index}-${Math.random().toString(36).slice(2, 7)}`;
    if (!isValidEmail(email)) return { key, email, name: row.name, error: "invalid" as const };
    const normalized = normalizeEmail(email);
    if (seen.has(normalized)) return { key, email, name: row.name, error: "duplicate" as const };
    seen.add(normalized);
    return { key, email, name: row.name };
  });
}

export function chunk<T>(items: T[], size: number): T[][] {
  const groups: T[][] = [];
  for (let index = 0; index < items.length; index += size) groups.push(items.slice(index, index + size));
  return groups;
}
