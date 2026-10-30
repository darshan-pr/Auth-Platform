"use client";

import { useEffect, useState } from "react";
import type { ConsoleAccount } from "../lib/types";
import { consoleApi } from "../lib/api";
import { ErrorBanner, Loading, PageHeader } from "./ui";
import { AccountDetails } from "./account-details";

export function ConsoleAccountPage() {
  const [account, setAccount] = useState<ConsoleAccount | null>(null); const [error, setError] = useState(""); useEffect(() => { consoleApi.me().then(setAccount).catch((err) => setError(err.message)); }, []);
  return <><PageHeader eyebrow="WORKSPACE" title="Account" description="Your developer console identity and access details." />{error && <ErrorBanner message={error} />}{!account && !error ? <Loading label="Loading account" /> : account && <AccountDetails account={{ ...account, status: "ACTIVE" }} showMfa />}</>;
}
