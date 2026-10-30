import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Protected page",
};

export default function ProtectedLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
