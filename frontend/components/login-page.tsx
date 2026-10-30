"use client";

import { useEffect, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { api, consoleApi } from "../lib/api";
import { Button, ErrorBanner, Field } from "./ui";
import { Icon } from "./icon";

type LoginStep = "credentials" | "login-otp" | "forgot-password" | "reset-password";

export function LoginPage({ sa = false }: { sa?: boolean }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [resetCode, setResetCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [step, setStep] = useState<LoginStep>("credentials");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    setMessage("");

    try {
      if (step === "credentials") {
        const result = sa
          ? await api.login(email, password)
          : await consoleApi.login(email, password);
        if (result.otpRequired && result.challengeId) {
          setChallengeId(result.challengeId);
          setMessage(result.message ?? "A one-time password was sent to your email address.");
          setStep("login-otp");
          return;
        }
        router.replace(sa ? "/overview" : "/console/overview");
        return;
      }

      if (step === "login-otp") {
        if (!challengeId) throw new Error("Your sign-in challenge has expired. Start again.");
        if (sa) await api.verifyOtp(challengeId, otpCode);
        else await consoleApi.verifyOtp(challengeId, otpCode);
        router.replace(sa ? "/overview" : "/console/overview");
        return;
      }

      if (step === "forgot-password") {
        const result = sa
          ? await api.forgotPassword(email)
          : await consoleApi.forgotPassword(email);
        setChallengeId(result.challengeId);
        setMessage(result.message);
        setStep("reset-password");
        return;
      }

      if (!challengeId) throw new Error("Your reset challenge has expired. Request a new code.");
      if (sa) await api.resetPassword(challengeId, resetCode, newPassword);
      else await consoleApi.resetPassword(challengeId, resetCode, newPassword);
      setStep("credentials");
      setPassword("");
      setOtpCode("");
      setResetCode("");
      setNewPassword("");
      setChallengeId("");
      setMessage("Password reset successfully. Sign in with your new password.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to complete the request");
    } finally {
      setLoading(false);
    }
  };

  const resendLoginOtp = async () => {
    if (!challengeId) {
      setError("Your sign-in challenge has expired. Start again.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const result = sa
        ? await api.resendLoginOtp(challengeId)
        : await consoleApi.resendLoginOtp(challengeId);
      setMessage(result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to resend the OTP");
    } finally {
      setLoading(false);
    }
  };

  const resendResetOtp = async () => {
    if (!challengeId) {
      setError("Your reset challenge has expired. Request a new code.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const result = sa
        ? await api.resendPasswordResetOtp(challengeId)
        : await consoleApi.resendPasswordResetOtp(challengeId);
      setMessage(result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to resend the reset code");
    } finally {
      setLoading(false);
    }
  };

  const startPasswordRecovery = () => {
    setStep("forgot-password");
    setError("");
    setMessage("");
  };

  const returnToSignIn = () => {
    setStep("credentials");
    setChallengeId("");
    setOtpCode("");
    setResetCode("");
    setNewPassword("");
    setError("");
    setMessage("");
  };

  const heading =
    step === "login-otp"
      ? "Enter your OTP"
      : step === "forgot-password"
        ? "Forgot your password?"
        : step === "reset-password"
          ? "Reset your password"
          : sa
            ? "Sign in as SA"
            : "Sign in to your console";
  const description =
    step === "login-otp"
      ? message
      : step === "forgot-password"
        ? "Enter your account email and we'll send a password reset code if the account exists."
        : step === "reset-password"
          ? message || "Enter the code from your email and choose a new password."
          : sa
            ? "Access platform-wide identity operations and audit controls."
            : "Create and manage applications, keys, and identity settings.";
  const pageTitle =
    step === "login-otp"
      ? "Verify sign in"
      : step === "forgot-password"
        ? "Forgot password"
        : step === "reset-password"
          ? "Reset password"
          : sa
            ? "SA sign in"
            : "Developer sign in";

  useEffect(() => {
    document.title = `${pageTitle} | Auth Platform`;
  }, [pageTitle]);

  return (
    <div className="login-page">
      <div className="login-panel">
        <div className="login-brand">
          <img alt="" className="brand-logo" src="/auth-platform-icon-black.png" />
          <span>Auth<span className="brand-accent"> Platform</span></span>
        </div>
        <div className="login-copy">
          <div className="eyebrow">{sa ? "SA CONSOLE" : "DEVELOPER CONSOLE"}</div>
          <h1>{heading}</h1>
          <p>{description}</p>
        </div>
        {error && <ErrorBanner message={error} />}
        {message && step !== "login-otp" && step !== "reset-password" && (
          <p className="auth-notice" role="status">{message}</p>
        )}
        <form onSubmit={submit} className="login-form">
          {step === "credentials" && (
            <>
              <Field
                autoComplete="email"
                label="Email address"
                onChange={(event) => setEmail(event.target.value)}
                placeholder="name@company.com"
                required
                type="email"
                value={email}
              />
              <Field
                autoComplete="current-password"
                label="Password"
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                required
                type="password"
                value={password}
              />
              <div className="login-form-links">
                <button className="auth-text-button" onClick={startPasswordRecovery} type="button">
                  Forgot password?
                </button>
              </div>
              <Button className="login-submit" disabled={loading}>
                {loading ? "Checking…" : "Continue"}<Icon name="chevronRight" size={16} />
              </Button>
            </>
          )}

          {step === "login-otp" && (
            <>
              <Field
                autoComplete="one-time-code"
                inputMode="numeric"
                label="One-time password (OTP)"
                maxLength={6}
                onChange={(event) => setOtpCode(event.target.value.replace(/\D/g, ""))}
                placeholder="Enter the 6-digit code from your email"
                required
                value={otpCode}
              />
              <Button className="login-submit" disabled={loading}>
                {loading ? "Verifying…" : "Verify OTP"}<Icon name="chevronRight" size={16} />
              </Button>
              <div className="login-form-links">
                <button
                  className="auth-text-button"
                  disabled={loading}
                  onClick={resendLoginOtp}
                  type="button"
                >
                  Resend OTP
                </button>
              </div>
              <Button
                className="login-back"
                onClick={returnToSignIn}
                type="button"
                variant="quiet"
              >
                Use different credentials
              </Button>
            </>
          )}

          {step === "forgot-password" && (
            <>
              <Field
                autoComplete="email"
                label="Email address"
                onChange={(event) => setEmail(event.target.value)}
                placeholder="name@company.com"
                required
                type="email"
                value={email}
              />
              <Button className="login-submit" disabled={loading}>
                {loading ? "Sending…" : "Send reset code"}<Icon name="chevronRight" size={16} />
              </Button>
              <Button className="login-back" onClick={returnToSignIn} type="button" variant="quiet">
                Back to sign in
              </Button>
            </>
          )}

          {step === "reset-password" && (
            <>
              <Field
                autoComplete="one-time-code"
                inputMode="numeric"
                label="Password reset code"
                maxLength={6}
                onChange={(event) => setResetCode(event.target.value.replace(/\D/g, ""))}
                placeholder="Enter the 6-digit code from your email"
                required
                value={resetCode}
              />
              <Field
                autoComplete="new-password"
                hint="10-128 characters, include a letter and a number, and don't include your email name."
                label="New password"
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder="Choose a new password"
                required
                type="password"
                value={newPassword}
              />
              <Button className="login-submit" disabled={loading}>
                {loading ? "Resetting…" : "Reset password"}<Icon name="chevronRight" size={16} />
              </Button>
              <div className="login-form-links">
                <button
                  className="auth-text-button"
                  disabled={loading}
                  onClick={resendResetOtp}
                  type="button"
                >
                  Resend reset code
                </button>
                <button className="auth-text-button" onClick={returnToSignIn} type="button">
                  Back to sign in
                </button>
              </div>
            </>
          )}
        </form>
        <div className={`login-note ${!sa && step === "credentials" ? "login-note-signup" : ""}`}>
          {sa ? (
            <><Icon name="shield" size={15} /> SA access is restricted to authorized platform operators.</>
          ) : step === "credentials" ? (
            <>New here? <a href="/signup">Create a console account</a><Icon name="chevronRight" size={14} /></>
          ) : (
            <><Icon name="shield" size={15} /> Your account recovery codes are sent to your registered email.</>
          )}
        </div>
      </div>
      <div className="login-footer">Auth Platform console <span>•</span> Local development environment</div>
    </div>
  );
}
