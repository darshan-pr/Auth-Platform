import type { Metadata } from "next";
import { Suspense } from "react";
import { VerifyEmailPage } from "../../components/verify-email-page";

export const metadata: Metadata = { title: "Verify email" };

type VerifyEmailRouteProps = {
  searchParams: Promise<{ token?: string | string[] }>;
};

export default function VerifyEmailRoute({ searchParams }: VerifyEmailRouteProps) {
  return (
    <Suspense fallback={<VerifyEmailPage token={null} />}>
      <VerifyEmailFromSearchParams searchParams={searchParams} />
    </Suspense>
  );
}

async function VerifyEmailFromSearchParams({ searchParams }: VerifyEmailRouteProps) {
  const { token } = await searchParams;
  const value = Array.isArray(token) ? token[0] ?? "" : token ?? "";
  return <VerifyEmailPage token={value} />;
}
