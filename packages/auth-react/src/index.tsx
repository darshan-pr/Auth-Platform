"use client";

import {
  AuthClient,
  AuthError,
  AuthSessionState,
  type ApplicationBranding,
  type AuthSession,
  type AuthUser,
  type MessageResponse,
  type SignUpInput,
  type SignupResponse,
  type SessionSnapshot
} from "@authplatform/auth-core";
import {
  createContext,
  type CSSProperties,
  type FormEvent,
  type InputHTMLAttributes,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState
} from "react";

export interface Appearance {
  variables?: Partial<Record<"primaryColor" | "textColor" | "backgroundColor" | "borderColor" | "radius", string>>;
  elements?: Partial<Record<"card" | "button" | "input" | "error", string>>;
}

export interface AuthProviderProps {
  children: ReactNode;
  client?: AuthClient;
  appearance?: Appearance;
  applicationName?: string;
  applicationIconUrl?: string;
  brandingRefreshIntervalMs?: number;
  checkSessionOnLoad?: boolean;
}

export interface AuthContextValue {
  client: AuthClient;
  snapshot: SessionSnapshot;
  user: AuthUser | null;
  isLoaded: boolean;
  isSignedIn: boolean;
  signIn: AuthClient["signIn"];
  verifyOtp: AuthClient["verifyOtp"];
  resendLoginOtp: AuthClient["resendLoginOtp"];
  cancelChallenge: () => void;
  signUp: AuthClient["signUp"];
  signOut: () => Promise<void>;
  retrySession: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);
const AppearanceContext = createContext<Appearance | undefined>(undefined);
type ApplicationContextValue = {
  name: string;
  iconUrl?: string;
  positionX: number;
  positionY: number;
  zoomPercent: number;
  error?: string;
};

const ApplicationContext = createContext<ApplicationContextValue>({
  name: "Application",
  positionX: 50,
  positionY: 50,
  zoomPercent: 100
});

function csrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  return document.cookie
    .split("; ")
    .find((item) => item.startsWith("authplatform_csrf="))
    ?.split("=")
    .slice(1)
    .join("=");
}

function cssFor(appearance?: Appearance): CSSProperties & Record<string, string> {
  const variables = appearance?.variables ?? {};
  return {
    "--auth-primary-color": variables.primaryColor ?? "#1769aa",
    "--auth-text-color": variables.textColor ?? "#172033",
    "--auth-background-color": variables.backgroundColor ?? "#ffffff",
    "--auth-border-color": variables.borderColor ?? "#dbe2e9",
    "--auth-radius": variables.radius ?? "8px"
  };
}

function hasAuthenticatedSession(result: Awaited<ReturnType<AuthClient["signIn"]>>): boolean {
  return result.authenticated && !result.otpRequired && result.user !== null;
}

function useApplicationFavicon(iconUrl?: string): void {
  useEffect(() => {
    if (!iconUrl) return;
    const currentLinks = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel~="icon"]'));
    const createdLink = currentLinks.length === 0;
    const links = createdLink ? [document.createElement("link")] : currentLinks;
    const originals = links.map((link) => ({
      link,
      href: link.getAttribute("href"),
      type: link.getAttribute("type")
    }));
    const mimeType = /^data:(image\/[a-z0-9.+-]+);/i.exec(iconUrl)?.[1];
    if (createdLink) links[0].rel = "icon";
    for (const link of links) {
      link.setAttribute("href", iconUrl);
      if (mimeType) link.setAttribute("type", mimeType);
      else link.removeAttribute("type");
    }
    if (createdLink) document.head.append(links[0]);
    return () => {
      if (createdLink) {
        links[0].remove();
        return;
      }
      for (const original of originals) {
        if (original.href === null) original.link.removeAttribute("href");
        else original.link.setAttribute("href", original.href);
        if (original.type === null) original.link.removeAttribute("type");
        else original.link.setAttribute("type", original.type);
      }
    };
  }, [iconUrl]);
}

export function AuthProvider({
  children,
  client,
  appearance,
  applicationName,
  applicationIconUrl,
  brandingRefreshIntervalMs = 0,
  checkSessionOnLoad = true
}: AuthProviderProps) {
  const resolvedClient = useMemo(() => client ?? new AuthClient({ csrfToken }), [client]);
  const sessionState = useMemo(() => new AuthSessionState(), []);
  const [snapshot, setSnapshot] = useState<SessionSnapshot>(sessionState.value);
  const [branding, setBranding] = useState<ApplicationContextValue>({
    name: applicationName ?? "Application",
    iconUrl: applicationIconUrl,
    positionX: 50,
    positionY: 50,
    zoomPercent: 100
  });

  useEffect(() => sessionState.subscribe(setSnapshot), [sessionState]);
  useEffect(() => {
    let active = true;
    let inFlight = false;
    let hasLoadedBranding = false;
    let lastRequestAt = 0;
    const refreshBranding = () => {
      if (
        !active ||
        inFlight ||
        document.visibilityState === "hidden" ||
        Date.now() - lastRequestAt < 1000
      ) return;
      inFlight = true;
      lastRequestAt = Date.now();
      resolvedClient.getApplicationBranding().then((result: ApplicationBranding) => {
        if (!active) return;
        hasLoadedBranding = true;
        const next: ApplicationContextValue = {
          name: applicationName ?? result.name,
          iconUrl: applicationIconUrl ?? result.iconDataUrl ?? result.iconUrl ?? undefined,
          positionX: result.iconPositionX,
          positionY: result.iconPositionY,
          zoomPercent: result.iconZoomPercent
        };
        setBranding((current) =>
          current.name === next.name &&
          current.iconUrl === next.iconUrl &&
          current.positionX === next.positionX &&
          current.positionY === next.positionY &&
          current.zoomPercent === next.zoomPercent &&
          current.error === undefined
            ? current
            : next
        );
      }).catch(() => {
        if (!active) return;
        const message = hasLoadedBranding
          ? "Application branding could not be refreshed."
          : "Application branding could not be loaded.";
        setBranding((current) => current.error === message
          ? current
          : { ...current, error: message });
      }).finally(() => {
        inFlight = false;
      });
    };
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") refreshBranding();
    };
    refreshBranding();
    window.addEventListener("focus", refreshBranding);
    document.addEventListener("visibilitychange", onVisibilityChange);
    const refreshInterval = brandingRefreshIntervalMs > 0
      ? window.setInterval(refreshBranding, Math.max(1000, brandingRefreshIntervalMs))
      : undefined;
    return () => {
      active = false;
      window.removeEventListener("focus", refreshBranding);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      if (refreshInterval !== undefined) window.clearInterval(refreshInterval);
    };
  }, [applicationIconUrl, applicationName, brandingRefreshIntervalMs, resolvedClient]);
  useApplicationFavicon(branding.iconUrl);

  const checkSession = useCallback(async (shouldUpdate: () => boolean = () => true) => {
    const previousUser = sessionState.value.user;
    sessionState.set({ status: "loading", user: previousUser });
    try {
      const user = await resolvedClient.getUser();
      if (shouldUpdate()) {
        sessionState.set(
          user
            ? { status: "authenticated", user }
            : { status: "unauthenticated", user: null }
        );
      }
    } catch {
      if (shouldUpdate()) {
        sessionState.set({
          status: "error",
          user: previousUser,
          error: "We couldn't verify your session. Your sign-in has been preserved. Please retry."
        });
      }
    }
  }, [resolvedClient, sessionState]);
  const retrySession = useCallback(() => checkSession(), [checkSession]);

  useEffect(() => {
    if (!checkSessionOnLoad) {
      sessionState.set({ status: "unauthenticated", user: null });
      return;
    }
    let active = true;
    void checkSession(() => active);
    return () => {
      active = false;
    };
  }, [checkSession, checkSessionOnLoad, sessionState]);

  const signIn = useCallback<AuthClient["signIn"]>(async (input) => {
    const result = await resolvedClient.signIn(input);
    if (result.otpRequired) {
      if (!result.challengeId) throw new AuthError("UNKNOWN_ERROR", 502);
      sessionState.set({
        status: "challenge",
        user: result.user,
        challengeId: result.challengeId,
        message: result.message
      });
    } else if (hasAuthenticatedSession(result)) {
      sessionState.set({ status: "authenticated", user: result.user });
    } else {
      throw new AuthError("UNKNOWN_ERROR", 502);
    }
    return result;
  }, [resolvedClient, sessionState]);

  const verifyOtp = useCallback<AuthClient["verifyOtp"]>(async (challengeId, code) => {
    const result = await resolvedClient.verifyOtp(challengeId, code);
    if (result.otpRequired) {
      if (!result.challengeId) throw new AuthError("UNKNOWN_ERROR", 502);
      sessionState.set({
        status: "challenge",
        user: result.user,
        challengeId: result.challengeId,
        message: result.message
      });
    } else if (hasAuthenticatedSession(result)) {
      sessionState.set({ status: "authenticated", user: result.user });
    } else {
      throw new AuthError("UNKNOWN_ERROR", 502);
    }
    return result;
  }, [resolvedClient, sessionState]);

  const resendLoginOtp = useCallback<AuthClient["resendLoginOtp"]>(async (challengeId) => {
    const result = await resolvedClient.resendLoginOtp(challengeId);
    if (sessionState.value.status === "challenge") {
      sessionState.set({ ...sessionState.value, message: result.message, error: undefined });
    }
    return result;
  }, [resolvedClient, sessionState]);

  const cancelChallenge = useCallback(() => {
    if (sessionState.value.status === "challenge") {
      sessionState.set({ status: "unauthenticated", user: null });
    }
  }, [sessionState]);

  const signUp = useCallback<AuthClient["signUp"]>(
    (input: SignUpInput) => resolvedClient.signUp(input),
    [resolvedClient]
  );

  const signOut = useCallback(async () => {
    try {
      await resolvedClient.signOut();
    } finally {
      sessionState.set({ status: "unauthenticated", user: null });
    }
  }, [resolvedClient, sessionState]);

  const refresh = useCallback(async () => {
    const result = await resolvedClient.refresh();
    if (!hasAuthenticatedSession(result)) throw new AuthError("UNAUTHENTICATED", 401);
    sessionState.set({ status: "authenticated", user: result.user });
  }, [resolvedClient, sessionState]);

  const value: AuthContextValue = {
    client: resolvedClient,
    snapshot,
    user: snapshot.user,
    isLoaded: snapshot.status !== "loading" && (snapshot.status !== "error" || snapshot.user !== null),
    isSignedIn: snapshot.status === "authenticated" || (snapshot.status === "error" && snapshot.user !== null),
    signIn,
    verifyOtp,
    resendLoginOtp,
    cancelChallenge,
    signUp,
    signOut,
    retrySession,
    refresh
  };

  return (
    <AuthContext.Provider value={value}>
      <ApplicationContext.Provider value={branding}>
        <AppearanceContext.Provider value={appearance}>{children}</AppearanceContext.Provider>
      </ApplicationContext.Provider>
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth() must be used inside <AuthProvider>");
  return value;
}

export function useUser(): { isLoaded: boolean; isSignedIn: boolean; user: AuthUser | null } {
  const { isLoaded, isSignedIn, user } = useAuth();
  return { isLoaded, isSignedIn, user };
}

export function useSession(): { isLoaded: boolean; isSignedIn: boolean; session: SessionSnapshot } {
  const { isLoaded, isSignedIn, snapshot } = useAuth();
  return { isLoaded, isSignedIn, session: snapshot };
}

function ErrorMessage({ error, className = "" }: { error: unknown; className?: string }) {
  const appearance = useContext(AppearanceContext);
  if (!error) return null;
  const message = error instanceof AuthError
    ? error.message
    : "Authentication request failed. Please try again.";
  return (
    <div className={`auth-error ${appearance?.elements?.error ?? ""} ${className}`} role="alert">
      <svg
        aria-hidden="true"
        fill="none"
        height="17"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        viewBox="0 0 24 24"
        width="17"
      >
        <path d="m12 3 9 17H3L12 3Z" />
        <path d="M12 9v4M12 17h.01" />
      </svg>
      <span>{message}</span>
    </div>
  );
}

type FieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, "onChange"> & {
  label: string;
  error?: string;
  hint?: string;
  onChange: (value: string) => void;
  elementClass?: string;
};

function Field({ label, error, hint, onChange, elementClass = "", ...props }: FieldProps) {
  const appearance = useContext(AppearanceContext);
  const generatedId = useId();
  const id = props.id ?? generatedId;
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(" ") || undefined;

  return (
    <div className="auth-field">
      <label htmlFor={id}>{label}</label>
      <input
        {...props}
        id={id}
        className={`auth-input ${appearance?.elements?.input ?? ""} ${elementClass} ${props.className ?? ""}`}
        aria-invalid={Boolean(error)}
        aria-describedby={describedBy}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint && <span id={hintId} className="auth-hint">{hint}</span>}
      {error && <span id={errorId} className="auth-field-error">{error}</span>}
    </div>
  );
}

function AuthCard({
  eyebrow,
  title,
  description,
  children,
  className = "",
  footer,
  footerClassName = ""
}: {
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
  className?: string;
  footer?: ReactNode;
  footerClassName?: string;
}) {
  const { snapshot } = useAuth();
  const appearance = useContext(AppearanceContext);
  const application = useContext(ApplicationContext);
  const [iconLoadFailed, setIconLoadFailed] = useState(false);
  useEffect(() => setIconLoadFailed(false), [application.iconUrl]);
  return (
    <section
      className={`auth-card ${appearance?.elements?.card ?? ""} ${className}`}
      style={cssFor(appearance)}
    >
      <div className="auth-brand" aria-label={application.name}>
        {application.iconUrl && !iconLoadFailed ? (
          <span className="auth-brand-icon-frame">
            <img
              className="auth-brand-icon"
              src={application.iconUrl}
              alt=""
              onError={() => setIconLoadFailed(true)}
              style={{
                objectPosition: `${application.positionX}% ${application.positionY}%`,
                transform: `scale(${application.zoomPercent / 100})`,
                transformOrigin: `${application.positionX}% ${application.positionY}%`
              }}
            />
          </span>
        ) : (
          <span className="auth-brand-mark" aria-hidden="true">
            <svg
              fill="none"
              height="19"
              stroke="currentColor"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="1.8"
              viewBox="0 0 24 24"
              width="19"
            >
              <path d="M12 3 20 6v5c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10V6l8-3Z" />
            </svg>
          </span>
        )}
        <span>{application.name}</span>
      </div>
      {application.error && <p className="auth-brand-error" role="status">{application.error}</p>}
      <div className="auth-heading">
        <span className="auth-eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {snapshot.error && <ErrorMessage error={new Error(snapshot.error)} />}
      {children}
      {footer && <div className={`auth-switch ${footerClassName}`}>{footer}</div>}
    </section>
  );
}

function ActionButton({
  children,
  appearanceClass,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { appearanceClass?: string }) {
  const appearance = useContext(AppearanceContext);
  return (
    <button {...props} className={`auth-button ${appearance?.elements?.button ?? ""} ${appearanceClass ?? ""} ${props.className ?? ""}`}>
      {children}
    </button>
  );
}

export function SignIn({ onSuccess }: { onSuccess?: () => void } = {}) {
  const { signIn, verifyOtp, resendLoginOtp, cancelChallenge, snapshot } = useAuth();
  const [mode, setMode] = useState<"sign-in" | "forgot-password">("sign-in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const fields = error instanceof AuthError ? error.fields : {};
  const isChallenge = mode === "sign-in" && snapshot.status === "challenge";

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      if (isChallenge) {
        if (!snapshot.challengeId) throw new AuthError("OTP_EXPIRED", 400);
        const result = await verifyOtp(snapshot.challengeId, code);
        if (result.authenticated) onSuccess?.();
      } else {
        const result = await signIn({ email, password });
        if (result.otpRequired) setPassword("");
        if (result.authenticated) onSuccess?.();
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const resend = async () => {
    if (!snapshot.challengeId) {
      setError(new AuthError("OTP_EXPIRED", 400));
      return;
    }
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      const result = await resendLoginOtp(snapshot.challengeId);
      setNotice(result.message);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  if (mode === "forgot-password") {
    return (
      <ForgotPassword
        onBack={() => {
          cancelChallenge();
          setMode("sign-in");
          setError(null);
          setNotice("");
        }}
        onSuccess={(response) => {
          setNotice(response.message);
          cancelChallenge();
          setMode("sign-in");
        }}
      />
    );
  }

  return (
    <AuthCard
      eyebrow="APPLICATION"
      title={isChallenge ? "Verify your email" : "Sign in"}
      footerClassName="auth-switch-end"
      description={isChallenge
        ? snapshot.message ?? "Enter the one-time code sent to your email."
        : "Sign in to continue to your account."}
      footer={
        !isChallenge
          ? <>New here? <a href="/sign-up">Create an account</a></>
          : undefined
      }
    >
      <form className="auth-form" onSubmit={submit} noValidate>
        <ErrorMessage error={error} />
        {notice && <p className="auth-notice" role="status">{notice}</p>}
        {isChallenge ? (
          <Field
            autoComplete="one-time-code"
            inputMode="numeric"
            label="One-time password"
            maxLength={6}
            value={code}
            onChange={(value) => setCode(value.replace(/\D/g, ""))}
            error={fields.code}
            placeholder="Enter 6-digit code"
          />
        ) : (
          <>
            <Field
              autoComplete="email"
              label="Email address"
              type="email"
              value={email}
              onChange={setEmail}
              error={fields.email}
              placeholder="name@example.com"
              required
            />
            <Field
              autoComplete="current-password"
              label="Password"
              type="password"
              value={password}
              onChange={setPassword}
              error={fields.password}
              placeholder="Enter your password"
              required
            />
          </>
        )}
        {!isChallenge && (
          <div className="auth-actions">
            <button
              className="auth-link-button"
              onClick={() => { setMode("forgot-password"); setError(null); setNotice(""); }}
              type="button"
            >
              Forgot password?
            </button>
          </div>
        )}
        <ActionButton disabled={busy}>
          {busy ? "Please wait…" : isChallenge ? "Verify code" : "Continue"}
          <span aria-hidden="true">→</span>
        </ActionButton>
        {isChallenge && (
          <div className="auth-actions">
            <button className="auth-link-button" disabled={busy} onClick={resend} type="button">
              Resend OTP
            </button>
            <button
              className="auth-link-button"
              onClick={() => {
                cancelChallenge();
                setError(null);
                setNotice("");
                setCode("");
              }}
              type="button"
            >
              Use different credentials
            </button>
          </div>
        )}
      </form>
    </AuthCard>
  );
}

export function SignUp({
  onSuccess
}: {
  onSuccess?: (response: SignupResponse) => void;
} = {}) {
  const { signUp, client } = useAuth();
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [resending, setResending] = useState(false);
  const fields = error instanceof AuthError ? error.fields : {};

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setMessage("");
    try {
      const response = await signUp(form);
      setMessage(response.message);
      onSuccess?.(response);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const resend = async () => {
    setResending(true);
    setError(null);
    try {
      const response = await client.resendVerification(form.email);
      setMessage(response.message);
    } catch (caught) {
      setError(caught);
    } finally {
      setResending(false);
    }
  };

  return (
    <AuthCard
      eyebrow="APPLICATION"
      title={message ? "Check your inbox" : "Create an account"}
      description={message
        ? message
        : "Create an account to get started with this application."}
      footer={<>Already have an account? <a href="/sign-in">Sign in</a></>}
    >
      {message ? (
        <div className="auth-success">
          <span className="auth-success-mark" aria-hidden="true">✓</span>
          <p role="status">Use the verification link in your email to activate your account.</p>
          <ErrorMessage error={error} />
          <ActionButton disabled={resending} onClick={resend} type="button" appearanceClass="auth-button-secondary">
            {resending ? "Sending…" : "Resend verification email"}
          </ActionButton>
        </div>
      ) : (
        <form className="auth-form" onSubmit={submit} noValidate>
          <ErrorMessage error={error} />
          <Field
            autoComplete="name"
            label="Full name"
            value={form.name}
            onChange={(name) => setForm({ ...form, name })}
            error={fields.name}
            placeholder="Your name"
            required
          />
          <Field
            autoComplete="email"
            label="Email address"
            type="email"
            value={form.email}
            onChange={(email) => setForm({ ...form, email })}
            error={fields.email}
            placeholder="name@example.com"
            required
          />
          <Field
            autoComplete="new-password"
            label="Password"
            type="password"
            value={form.password}
            onChange={(password) => setForm({ ...form, password })}
            error={fields.password}
            placeholder="Create a password"
            hint="10-128 characters; include a letter and a number."
            required
          />
          <ActionButton disabled={busy}>
            {busy ? "Creating account…" : "Create account"}
            <span aria-hidden="true">→</span>
          </ActionButton>
        </form>
      )}
    </AuthCard>
  );
}

export function VerifyEmail({ token }: { token: string }) {
  const { client } = useAuth();
  const [status, setStatus] = useState<"verifying" | "verified" | "error">("verifying");
  const [error, setError] = useState<unknown>(null);
  const currentToken = useRef(token);
  const verificationRequest = useRef<{
    token: string;
    promise: ReturnType<AuthClient["verifyEmail"]>;
  } | null>(null);

  useEffect(() => {
    currentToken.current = token;
    if (!token) {
      setError(new AuthError("TOKEN_INVALID", 400));
      setStatus("error");
      return;
    }

    setError(null);
    setStatus("verifying");
    if (!verificationRequest.current || verificationRequest.current.token !== token) {
      verificationRequest.current = { token, promise: client.verifyEmail(token) };
    }
    verificationRequest.current.promise.then(
      () => {
        if (currentToken.current === token) setStatus("verified");
      },
      (caught) => {
        if (currentToken.current === token) {
          setError(caught);
          setStatus("error");
        }
      }
    );
  }, [client, token]);

  return (
    <AuthCard
      eyebrow="EMAIL VERIFICATION"
      title={status === "verified" ? "Email verified" : status === "error" ? "Verification failed" : "Verify your email"}
      description={
        status === "verified"
          ? "Your email address is verified. You can now sign in."
          : status === "error"
            ? "This verification link may have expired or already been used."
            : "Confirming your email address."
      }
      footer={<a href="/sign-in">Back to sign in</a>}
    >
      {status === "verifying" && (
        <p className="auth-notice" role="status">Verifying your email…</p>
      )}
      {status === "verified" && (
        <div className="auth-success">
          <span className="auth-success-mark" aria-hidden="true">✓</span>
          <p role="status">Your account is ready to use.</p>
        </div>
      )}
      {status === "error" && (
        <>
          <ErrorMessage error={error} />
          <p className="auth-notice" role="status">
            Request a new verification email from the sign-up page and try again.
          </p>
        </>
      )}
    </AuthCard>
  );
}

export function ForgotPassword({
  onSuccess,
  onBack
}: {
  onSuccess?: (response: MessageResponse) => void;
  onBack?: () => void;
} = {}) {
  const { client } = useAuth();
  const [step, setStep] = useState<"email" | "code" | "complete">("email");
  const [email, setEmail] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const fields = error instanceof AuthError ? error.fields : {};

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      if (step === "email") {
        const result = await client.startPasswordReset(email);
        setChallengeId(result.challengeId);
        setNotice(result.message);
        setStep("code");
      } else {
        const result = await client.resetPasswordWithOtp(challengeId, code, password);
        setNotice(result.message);
        onSuccess?.(result);
        setStep("complete");
        setEmail("");
        setChallengeId("");
        setCode("");
        setPassword("");
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const resend = async () => {
    if (!challengeId) {
      setError(new AuthError("OTP_EXPIRED", 400));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await client.resendPasswordResetOtp(challengeId);
      setNotice(result.message);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthCard
      eyebrow="ACCOUNT RECOVERY"
      title={step === "email" ? "Forgot your password?" : step === "complete" ? "Password updated" : "Reset your password"}
      description={step === "email"
        ? "Enter your email and we'll send a reset code if the account exists."
        : step === "complete" ? notice : notice || "Enter the code sent to your email and choose a new password."}
      footer="Password reset codes are sent to your registered email."
    >
      {step === "complete" ? (
        <div className="auth-success">
          <span className="auth-success-mark" aria-hidden="true">✓</span>
          <p role="status">Your password has been updated. You can now sign in.</p>
          {onBack && <ActionButton onClick={onBack} type="button">Back to sign in</ActionButton>}
        </div>
      ) : (
        <form className="auth-form" onSubmit={submit} noValidate>
          <ErrorMessage error={error} />
          {step === "email" ? (
          <Field
            autoComplete="email"
            label="Email address"
            type="email"
            value={email}
            onChange={setEmail}
            error={fields.email}
            placeholder="name@example.com"
            required
          />
          ) : (
          <>
            {notice && <p className="auth-notice" role="status">{notice}</p>}
            <Field
              autoComplete="one-time-code"
              inputMode="numeric"
              label="Password reset code"
              maxLength={6}
              value={code}
              onChange={(value) => setCode(value.replace(/\D/g, ""))}
              error={fields.code}
              placeholder="Enter 6-digit code"
              required
            />
            <Field
              autoComplete="new-password"
              label="New password"
              type="password"
              value={password}
              onChange={setPassword}
              error={fields.newPassword}
              hint="10-128 characters; include a letter and a number."
              placeholder="Choose a new password"
              required
            />
          </>
          )}
          <ActionButton disabled={busy}>
            {busy ? "Please wait…" : step === "email" ? "Send reset code" : "Reset password"}
            <span aria-hidden="true">→</span>
          </ActionButton>
          <div className="auth-actions">
            {step === "code" && (
              <button className="auth-link-button" disabled={busy} onClick={resend} type="button">
                Resend reset code
              </button>
            )}
            {(step === "code" || onBack) && (
              <button
                className="auth-link-button"
                onClick={() => {
                  if (step === "code") {
                    setStep("email");
                    setChallengeId("");
                    setCode("");
                    setPassword("");
                    setNotice("");
                  }
                  onBack?.();
                }}
                type="button"
              >
                {onBack ? "Back to sign in" : "Use a different email"}
              </button>
            )}
          </div>
        </form>
      )}
    </AuthCard>
  );
}

export function UserButton() {
  const { client, user, isLoaded, isSignedIn, signOut, snapshot, retrySession } = useAuth();
  const appearance = useContext(AppearanceContext);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [sessions, setSessions] = useState<AuthSession[]>([]);
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [pendingSession, setPendingSession] = useState("");
  if (snapshot.status === "error" && !user) {
    return (
      <div className={`auth-error ${appearance?.elements?.error ?? ""}`} role="alert">
        <span>{snapshot.error}</span>
        <button onClick={() => void retrySession()} type="button">Retry session check</button>
      </div>
    );
  }
  if (!isLoaded) return <span aria-live="polite">Loading…</span>;
  if (!isSignedIn || !user) return <ErrorMessage error={error} />;

  const logout = async () => {
    setBusy(true);
    setError(null);
    try {
      const activeSessions = await client.getSessions();
      if (activeSessions.some((session) => !session.current)) {
        setSessions(activeSessions);
        setSessionsOpen(true);
        return;
      }
      await signOut();
    } catch (caught) {
      setSessions([]);
      setSessionsOpen(true);
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const finishSignOut = async () => {
    setBusy(true);
    setError(null);
    try {
      await signOut();
      setSessionsOpen(false);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const revokeSession = async (session: AuthSession) => {
    setPendingSession(session.id);
    setError(null);
    try {
      await client.revokeSession(session.id);
      setSessions((current) => current.filter((item) => item.id !== session.id));
    } catch (caught) {
      setError(caught);
    } finally {
      setPendingSession("");
    }
  };

  return (
    <div className="auth-user-button" style={cssFor(appearance)}>
      <span aria-label={`Signed in as ${user.email}`}>{user.email}</span>
      <ActionButton
        type="button"
        disabled={busy}
        onClick={logout}
        appearanceClass="auth-button-secondary"
      >
        {busy ? "Signing out…" : "Sign out"}
      </ActionButton>
      <ErrorMessage error={error} />
      {sessionsOpen && <div className="auth-session-backdrop"><section aria-labelledby="auth-sessions-title" aria-modal="true" className="auth-session-dialog" role="dialog">
        <div className="auth-session-heading"><div><h2 id="auth-sessions-title">Signed-in devices</h2><p>Review other active sessions before signing out.</p></div><button aria-label="Close session dialog" className="auth-session-close" onClick={() => setSessionsOpen(false)} type="button">×</button></div>
        {error ? <ErrorMessage error={error} /> : null}
        <div className="auth-session-list">{sessions.map((session) => <div className="auth-session-row" key={session.id}>
          <div><strong>{authDeviceName(session.userAgent)}{session.current && <span className="auth-session-current">This device</span>}</strong><small>{session.ipAddress || "Unknown IP"} · Last active {authSessionDate(session.lastActiveAt)}</small></div>
          {!session.current && <button className="auth-session-revoke" disabled={pendingSession === session.id} onClick={() => revokeSession(session)} type="button">{pendingSession === session.id ? "Revoking…" : "Revoke"}</button>}
        </div>)}</div>
        <div className="auth-session-actions"><button className="auth-session-cancel" onClick={() => setSessionsOpen(false)} type="button">Stay signed in</button><button className="auth-session-signout" disabled={busy} onClick={finishSignOut} type="button">{busy ? "Signing out…" : "Sign out here"}</button></div>
      </section></div>}
    </div>
  );
}

function authDeviceName(userAgent: string | null): string {
  if (!userAgent) return "Unknown device";
  const browser = userAgent.includes("Firefox") ? "Firefox" : userAgent.includes("Edg/") ? "Edge" : userAgent.includes("Chrome/") ? "Chrome" : userAgent.includes("Safari/") ? "Safari" : "Browser";
  const os = userAgent.includes("iPhone") || userAgent.includes("iPad") ? "iOS" : userAgent.includes("Android") ? "Android" : userAgent.includes("Windows") ? "Windows" : userAgent.includes("Mac OS") ? "macOS" : userAgent.includes("Linux") ? "Linux" : "device";
  return `${browser} on ${os}`;
}

function authSessionDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
