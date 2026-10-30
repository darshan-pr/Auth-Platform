export type PlatformRole = "USER" | "SA";

export type PageResponse<T> = {
  items: T[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type Account = {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  platformRole: PlatformRole;
  status: string;
  createdAt: string;
  appCount: number;
};

export type App = {
  id: string;
  name: string;
  publishableKey: string;
  ownerAccountId: string;
  ownerEmail: string;
  allowedOrigins: string[];
  requireEmailVerification: boolean;
  mfaRequired: boolean;
  accessTokenTtlSeconds: number | null;
  refreshTokenTtlSeconds: number | null;
  status: string;
  createdAt: string;
  secretKeyHint: string | null;
  userCount: number;
};

export type AppUser = {
  id: string;
  appId: string;
  name: string;
  email: string;
  emailVerified: boolean;
  status: string;
  lastLoginAt: string | null;
  createdAt: string;
};

export type SessionInfo = {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  current: boolean;
};

export type AppUserActivity = {
  id: number;
  action: string;
  actorType: string;
  ipAddress: string | null;
  requestId: string | null;
  createdAt: string;
  metadata: Record<string, unknown> | null;
};

export type AppUserDetails = {
  user: AppUser;
  roles: Role[];
  userRolePermissions?: UserRolePermissions[];
  permissions: string[];
  history: AppUserActivity[];
};

export type Analytics = {
  totalAccounts: number;
  activeAccounts: number;
  verifiedAccounts: number;
  totalApps: number;
  activeApps: number;
  totalAppUsers: number;
  activeAppUsers: number;
  usersByApp: { appId: string; appName: string; userCount: number }[];
};

export type AuditLog = {
  id: number;
  appId: string | null;
  actorAccountId: string | null;
  actorAppUserId: string | null;
  actorType: string;
  action: string;
  ipAddress: string | null;
  requestId: string | null;
  createdAt: string;
  metadata: Record<string, unknown> | null;
};

export type AccountDetails = { account: Account; apps: App[] };

export type RotatedSecret = { appId: string; secretKey: string; secretKeyHint: string };

export type ConsoleAccount = { id: string; name: string; email: string; platformRole: string };

export type ConsoleApp = {
  id: string;
  name: string;
  publishableKey: string;
  allowedOrigins: string[];
  verifyEmailUrl: string | null;
  requireEmailVerification: boolean;
  mfaRequired: boolean;
  accessTokenTtlSeconds: number | null;
  refreshTokenTtlSeconds: number | null;
  status: string;
  createdAt: string;
  secretKeyHint: string | null;
  defaultRole: { id: string; name: string };
  iconUrl: string | null;
  iconDataUrl: string | null;
  iconPositionX: number;
  iconPositionY: number;
  iconZoomPercent: number;
};

export type MfaStatus = { required: boolean; enabled: boolean; setupRequired: boolean };
export type LoginChallenge = { authenticated: false; otpRequired: true; challengeId: string; message: string; expiresIn: number };
export type LoginResponse<T> = LoginChallenge | { authenticated?: true; otpRequired?: false; account: T; expiresIn: number };
export type OtpChallenge = { challengeId: string; expiresIn: number; message: string };
export type Role = { id: string; name: string; displayName: string | null; description: string | null; defaultRole: boolean; enabled: boolean; permissions: string[]; userCount: number };
export type Permission = {
  id: string;
  roleId: string;
  key: string;
  description: string | null;
  enabled: boolean;
};
export type RolePermissionUser = {
  id: string;
  name: string;
  email: string;
  status: string;
  permissionEnabled: boolean;
};
export type UserRolePermissions = { roleId: string; permissionKeys: string[] };
