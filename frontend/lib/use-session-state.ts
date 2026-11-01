"use client";

import { useEffect, useState } from "react";
import { api, consoleApi } from "./api";

export type SessionState = { console: boolean; sa: boolean };

const HINT_KEY = "authplatform.session-hint";
let probe: Promise<SessionState> | null = null;

function readHint(): SessionState | null {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(HINT_KEY) ?? "null") as SessionState | null;
    return value && typeof value.console === "boolean" && typeof value.sa === "boolean" ? value : null;
  } catch {
    return null;
  }
}

function probeSessions(): Promise<SessionState> {
  probe ??= Promise.all([
    consoleApi.me().then(() => true, () => false),
    api.me().then(() => true, () => false),
  ]).then(([consoleSession, saSession]) => {
    const state = { console: consoleSession, sa: saSession };
    try { window.sessionStorage.setItem(HINT_KEY, JSON.stringify(state)); } catch { /* best effort */ }
    return state;
  }).finally(() => { window.setTimeout(() => { probe = null; }, 5000); });
  return probe;
}

/**
 * Whether the visitor already has a console and/or SA session. Returns null until known.
 * The last answer is remembered for the tab so later page views do not flicker.
 */
export function useSessionState(): SessionState | null {
  const [state, setState] = useState<SessionState | null>(null);
  useEffect(() => {
    let active = true;
    const hint = readHint();
    if (hint) setState(hint);
    probeSessions().then((next) => { if (active) setState(next); });
    return () => { active = false; };
  }, []);
  return state;
}
