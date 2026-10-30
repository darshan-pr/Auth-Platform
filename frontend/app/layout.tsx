import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "Auth Platform",
    template: "%s | Auth Platform",
  },
  description: "Identity platform administration console",
  icons: {
    icon: [
      { url: "/auth-platform-icon-black.png", media: "(prefers-color-scheme: light)" },
      { url: "/auth-platform-icon-white.png", media: "(prefers-color-scheme: dark)" },
    ],
    apple: "/auth-platform-icon-black.png",
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
