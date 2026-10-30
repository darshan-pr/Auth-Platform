import type { Metadata } from "next";
import { AuthProvider } from "@authplatform/auth-react";
import "@authplatform/auth-react/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "Auth Platform",
    template: "%s | Auth Platform",
  },
  description: "Installed-package integration test for Auth Platform",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><AuthProvider brandingRefreshIntervalMs={5000} checkSessionOnLoad={false}>{children}</AuthProvider></body></html>;
}
