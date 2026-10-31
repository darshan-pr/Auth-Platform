"use client";

import Link from "next/link";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { consoleApi } from "../lib/api";
import { Button, ErrorBanner, Field } from "./ui";

type Status = "pending" | "verifying" | "verified" | "error";

// `token === null` means the token is still being read from the URL.
export function VerifyEmailPage({ token }: { token: string | null }) {
  const [status, setStatus] = useState<Status>("pending");
  const [error, setError] = useState("");
  const [resendEmail, setResendEmail] = useState("");
  const [resendMessage, setResendMessage] = useState("");
  const [resending, setResending] = useState(false);
  // Tokens are single-use, so React Strict Mode must not submit the same token twice.
  const request = useRef<{ token: string; promise: Promise<unknown> } | null>(null);

  useEffect(() => {
    document.title = "Verify email | Auth Platform";
  }, []);

  useEffect(() => {
    if (token === null) return;
    if (!token) {
      setError("This verification link is missing its token.");
      setStatus("error");
      return;
    }
    let current = true;
    setStatus("verifying");
    setError("");
    if (!request.current || request.current.token !== token) {
      request.current = { token, promise: consoleApi.verifyEmail(token) };
    }
    request.current.promise.then(
      () => { if (current) setStatus("verified"); },
      (err) => {
        if (!current) return;
        setError(err instanceof Error ? err.message : "Unable to verify your email.");
        setStatus("error");
      },
    );
    return () => { current = false; };
  }, [token]);

  const resend = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setResending(true);
    setResendMessage("");
    try {
      const result = await consoleApi.resendVerification(resendEmail);
      setResendMessage(result.message);
    } catch (err) {
      setResendMessage(err instanceof Error ? err.message : "Unable to resend the verification email.");
    } finally {
      setResending(false);
    }
  };

  const title = status === "verified" ? "Email verified" : status === "error" ? "Verification failed" : "Verify your email";
  const description = status === "verified"
    ? "Your email address is verified. You can now sign in."
    : status === "error"
      ? "This verification link may have expired or already been used."
      : "Confirming your email address.";

  return (
    <div className="login-page">
      <div className="login-panel">
        <div className="login-brand">
          <img alt="" className="brand-logo" src="/auth-platform-icon-black.png" />
          <span>Auth<span className="brand-accent"> Platform</span></span>
        </div>
        <div className="login-copy">
          <div className="eyebrow">EMAIL VERIFICATION</div>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
        {(status === "pending" || status === "verifying") && (
          <p className="auth-notice" role="status">Verifying your email…</p>
        )}
        {status === "verified" && (
          <div className="success-panel">
            <span className="success-icon">✓</span>
            <strong>Your account is ready to use.</strong>
            <Link className="button button-primary" href="/login">Continue to sign in</Link>
          </div>
        )}
        {status === "error" && (
          <>
            <ErrorBanner message={error} />
            <form className="login-form" onSubmit={resend}>
              <Field
                autoComplete="email"
                label="Email address"
                onChange={(event) => setResendEmail(event.target.value)}
                placeholder="name@company.com"
                required
                type="email"
                value={resendEmail}
              />
              {resendMessage && <p className="auth-notice" role="status">{resendMessage}</p>}
              <Button className="login-submit" disabled={resending}>
                {resending ? "Sending…" : "Send a new verification email"}
              </Button>
            </form>
          </>
        )}
        <div className="login-note">
          <Link href="/login">Back to sign in</Link>
        </div>
      </div>
      <div className="login-footer">Auth Platform console</div>
    </div>
  );
}
