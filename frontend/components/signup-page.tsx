"use client";

import Link from "next/link";
import { useEffect, useState, type FormEvent } from "react";
import { consoleApi } from "../lib/api";
import { Button, ErrorBanner, Field } from "./ui";
import { Icon } from "./icon";

export function SignupPage() {
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);

  useEffect(() => {
    document.title = "Create account | Auth Platform";
  }, []);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const result = await consoleApi.signup(form);
      setMessage(result.message || "Check your email to verify your account.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to create account");
    } finally {
      setLoading(false);
    }
  };

  const resendVerification = async () => {
    setResending(true);
    setError("");
    try {
      const result = await consoleApi.resendVerification(form.email);
      setMessage(result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to resend the verification email");
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-panel">
        <div className="login-brand">
          <img alt="" className="brand-logo" src="/auth-platform-icon-black.png" />
          <span>Auth<span className="brand-accent"> Platform</span></span>
        </div>
        <div className="login-copy">
          <div className="eyebrow">DEVELOPER CONSOLE</div>
          <h1>Create your console account</h1>
          <p>Register an account to create and manage your own identity applications.</p>
        </div>
        {error && <ErrorBanner message={error} />}
        {message ? (
          <div className="success-panel">
            <span className="success-icon">✓</span>
            <strong>Check your inbox</strong>
            <p role="status">{message}</p>
            <Button disabled={resending} onClick={resendVerification} type="button" variant="secondary">
              {resending ? "Sending…" : "Resend verification email"}
            </Button>
            <Link className="button button-primary" href="/login">Return to sign in</Link>
          </div>
        ) : (
          <form onSubmit={submit} className="login-form">
            <Field
              autoComplete="name"
              label="Full name"
              onChange={(event) => setForm({ ...form, name: event.target.value })}
              placeholder="Your name"
              required
              value={form.name}
            />
            <Field
              autoComplete="email"
              label="Email address"
              onChange={(event) => setForm({ ...form, email: event.target.value })}
              placeholder="name@company.com"
              required
              type="email"
              value={form.email}
            />
            <Field
              autoComplete="new-password"
              hint="At least 10 characters, with at least one letter and one number."
              label="Password"
              onChange={(event) => setForm({ ...form, password: event.target.value })}
              placeholder="Create a password"
              required
              type="password"
              value={form.password}
            />
            <Button className="login-submit" disabled={loading}>
              {loading ? "Creating…" : "Create account"}<Icon name="chevronRight" size={16} />
            </Button>
          </form>
        )}
        <div className="login-note">
          <Icon name="shield" size={15} /> Already have an account? <Link href="/login">Sign in</Link>
        </div>
      </div>
      <div className="login-footer">Auth Platform console <span>•</span> Local development environment</div>
    </div>
  );
}
