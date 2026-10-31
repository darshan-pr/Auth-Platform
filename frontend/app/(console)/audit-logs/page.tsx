import { Suspense } from "react";
import { AuditLogsPage } from "../../../components/audit-logs-page";

export const instant = false;

export default function AuditLogsRoute() {
  return <Suspense fallback={null}><AuditLogsPage /></Suspense>;
}
