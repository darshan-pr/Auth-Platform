"use client";

import type { ReactNode } from "react";

export function TestAuthLayout({ children }: { children: ReactNode }) {
  return (
    <main className="test-auth-placement">
      <div className="test-auth-content">
        {children}
        <footer className="test-auth-footer">Protected by Auth Platform.</footer>
      </div>
    </main>
  );
}
