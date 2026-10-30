import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Permission checks",
};

export default function PermissionsLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
