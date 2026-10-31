"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import type { App } from "../lib/types";
import { api } from "../lib/api";
import { Button, ErrorBanner, PageHeader } from "./ui";
import { EndUsersTable } from "./end-users-table";

export function UsersPage() {
  const params = useSearchParams();
  const [apps, setApps] = useState<App[]>([]);
  const [appId, setAppId] = useState(params.get("appId") ?? "all");
  const [reloadKey, setReloadKey] = useState(0);
  const [error, setError] = useState("");
  const initialQuery = params.get("q") ?? "";

  useEffect(() => { setAppId(params.get("appId") ?? "all"); }, [params]);
  useEffect(() => { api.apps(0, 100).then((result) => setApps(result.items)).catch((err) => setError(err.message)); }, []);

  return <>
    <PageHeader title="End users" description="Inspect and update users across every application." actions={<Button variant="secondary" icon="refresh" onClick={() => setReloadKey((key) => key + 1)}>Refresh</Button>} />
    {error && <ErrorBanner message={error} />}
    <EndUsersTable mode="sa" appId={appId} apps={apps} onAppChange={setAppId} initialQuery={initialQuery} description="Inspect and update users across every application." reloadKey={reloadKey} />
  </>;
}
