"use client";

import { useRouter } from "next/navigation";
import { SignIn } from "@authplatform/auth-react";
import { TestAuthLayout } from "../test-auth-layout";

export default function SignInPage() {
  const router = useRouter();
  return <TestAuthLayout><SignIn onSuccess={() => router.replace("/protected")} /></TestAuthLayout>;
}
