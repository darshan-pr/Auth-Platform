import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Server current user",
};

export default function ServerUserLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
