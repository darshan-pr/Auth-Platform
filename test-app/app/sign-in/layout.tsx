import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "SDK sign in",
};

export default function SignInLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
