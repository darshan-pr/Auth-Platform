"use client";

import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Account } from "../lib/types";
import { AccountDetails } from "./account-details";
import { ErrorBanner, Loading, PageHeader } from "./ui";

export function SaAccountPage() {
  const [account, setAccount] = useState<Account | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { api.me().then(setAccount).catch((err) => setError(err.message)); }, []);
  return <><PageHeader eyebrow="PLATFORM ADMINISTRATION" title="Account" description="Your platform administration identity and security settings." />{error && <ErrorBanner message={error} />}{!account && !error ? <Loading label="Loading account" /> : account && <AccountDetails account={account} showMfa mfaScope="sa" />}</>;
}
