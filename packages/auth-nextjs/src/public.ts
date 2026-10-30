import type { AuthUser } from "@authplatform/auth-core";

type Payload = Record<string, unknown>;
type PublicPayload = Payload | Payload[];

export function publicUser(value: unknown): AuthUser | null {
  if (!value || typeof value !== "object") return null;
  const data = value as Payload;
  if (typeof data.id !== "string" || typeof data.email !== "string") return null;
  return {
    id: data.id,
    name: typeof data.name === "string" ? data.name : "",
    email: data.email,
    emailVerified: data.emailVerified === true,
    roles: Array.isArray(data.roles) ? data.roles.filter((role): role is string => typeof role === "string") : [],
    permissions: Array.isArray(data.permissions) ? data.permissions.filter((permission): permission is string => typeof permission === "string") : []
  };
}

export function publicSuccess(path: string, value: unknown): PublicPayload {
  if (path === "application") {
    const data = value && typeof value === "object" ? value as Payload : {};
    const name = typeof data.name === "string" ? data.name.trim().slice(0, 100) : "";
    const iconUrl = typeof data.iconUrl === "string" &&
      (/^https:\/\/[^/\s?#]+(?:[/?#]|$)/i.test(data.iconUrl) ||
        /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(data.iconUrl))
      ? data.iconUrl.slice(0, 2048)
      : null;
    const iconDataUrl = typeof data.iconDataUrl === "string" &&
      data.iconDataUrl.length <= 500_000 &&
      /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(data.iconDataUrl)
      ? data.iconDataUrl
      : null;
    const boundedNumber = (item: unknown, min: number, max: number, fallback: number) =>
      typeof item === "number" && Number.isInteger(item) && item >= min && item <= max
        ? item
        : fallback;
    return {
      name: name || "Application",
      iconUrl,
      iconDataUrl,
      iconPositionX: boundedNumber(data.iconPositionX, 0, 100, 50),
      iconPositionY: boundedNumber(data.iconPositionY, 0, 100, 50),
      iconZoomPercent: boundedNumber(data.iconZoomPercent, 100, 300, 100)
    };
  }
  if (path === "sessions" && Array.isArray(value)) {
    return value
      .filter((item): item is Payload => Boolean(item && typeof item === "object"))
      .filter((item) =>
        typeof item.id === "string" &&
        typeof item.createdAt === "string" &&
        typeof item.lastActiveAt === "string" &&
        typeof item.expiresAt === "string"
      )
      .map((item) => ({
        id: item.id,
        ipAddress: typeof item.ipAddress === "string" ? item.ipAddress : null,
        userAgent: typeof item.userAgent === "string" ? item.userAgent : null,
        createdAt: item.createdAt,
        lastActiveAt: item.lastActiveAt,
        expiresAt: item.expiresAt,
        current: item.current === true
      }));
  }
  const data = value && typeof value === "object" ? value as Payload : {};
  if (path === "signup") {
    const user = publicUser(data);
    return {
      id: user?.id ?? null,
      email: user?.email ?? "",
      emailVerified: user?.emailVerified === true,
      message: "Account created. Please verify your email."
    };
  }
  if (path === "verify-email") return { emailVerified: data.emailVerified === true };
  if (path === "resend-verification" || path === "forgot-password") {
    return { message: "If the account exists, an email has been sent" };
  }
  if (path === "forgot-password/otp" || path === "forgot-password/otp/resend") {
    return {
      message: "If the account exists, a one-time password was sent to its email address.",
      ...(typeof data.challengeId === "string" ? { challengeId: data.challengeId } : {}),
      ...(typeof data.expiresIn === "number" ? { expiresIn: data.expiresIn } : {})
    };
  }
  if (path === "reset-password") return { message: "Password reset successfully" };
  if (path === "reset-password/otp") return { message: "Password reset successfully" };
  if (path === "me") {
    const user = publicUser(data);
    return user ? { ...user } : {};
  }
  if (path === "mfa/status") {
    return {
      required: data.required === true,
      enabled: data.enabled === true,
      setupRequired: data.setupRequired === true
    };
  }
  return {};
}

export function publicLogin(value: unknown): Payload {
  const data = value && typeof value === "object" ? value as Payload : {};
  const otpRequired = data.otpRequired === true;
  return {
    authenticated: !otpRequired && typeof data.accessToken === "string" && typeof data.refreshToken === "string",
    ...(otpRequired ? {} : { user: publicUser(data.user) }),
    otpRequired,
    ...(typeof data.challengeId === "string" ? { challengeId: data.challengeId } : {}),
    expiresIn: typeof data.expiresIn === "number" ? data.expiresIn : 0,
    ...(typeof data.refreshExpiresIn === "number" ? { refreshExpiresIn: data.refreshExpiresIn } : {}),
    ...(typeof data.message === "string" ? { message: data.message } : {})
  };
}
