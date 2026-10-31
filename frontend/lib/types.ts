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
  invited: boolean;
};

export type UserListParams = {
  q?: string;
  status?: string;
  sort?: string;
  direction?: "asc" | "desc";
  size?: number;
};

export type InviteeInput = { email: string; name?: string };
export type InviteOutcome = "INVITED" | "ALREADY_EXISTS" | "DUPLICATE" | "INVALID";
export type InviteResult = { email: string; outcome: InviteOutcome; message: string };
export type InviteResponse = { requested: number; invited: number; skipped: number; results: InviteResult[] };

export type SearchType = "ACCOUNT" | "APPLICATION" | "END_USER" | "AUDIT_EVENT";
export type SearchHit = {
  type: SearchType;
  id: string;
  title: string;
  subtitle: string | null;
  status: string | null;
  appId: string | null;
  appName: string | null;
};
export type SearchGroup = { type: SearchType; items: SearchHit[]; hasMore: boolean };
export type SearchResponse = { query: string; groups: SearchGroup[] };

export type SessionInfo = {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  current: boolean;
};

export type AppUserDetails = {
  user: AppUser;
  roles: Role[];
  userRolePermissions?: UserRolePermissions[];
  permissions: string[];
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
