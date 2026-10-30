import { Suspense } from "react";
import { ConsoleShell } from "../../components/console-shell";

export const instant = false;

export default function ConsoleLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <Suspense fallback={<div className="shell-loading">Loading console…</div>}><ConsoleShell>{children}</ConsoleShell></Suspense>;
}
