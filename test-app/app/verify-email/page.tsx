import { Suspense } from "react";
import { VerifyEmail } from "@authplatform/auth-react";
import { TestAuthLayout } from "../test-auth-layout";

type VerifyEmailPageProps = {
  searchParams: Promise<{ token?: string | string[] }>;
};

export default function VerifyEmailPage({ searchParams }: VerifyEmailPageProps) {
  return (
    <TestAuthLayout>
      <Suspense fallback={<p className="auth-notice" role="status">Loading verification…</p>}>
        <VerifyEmailFromSearchParams searchParams={searchParams} />
      </Suspense>
    </TestAuthLayout>
  );
}

async function VerifyEmailFromSearchParams({ searchParams }: VerifyEmailPageProps) {
  const { token } = await searchParams;
  const value = Array.isArray(token) ? token[0] ?? "" : token ?? "";

  return <VerifyEmail token={value} />;
}
