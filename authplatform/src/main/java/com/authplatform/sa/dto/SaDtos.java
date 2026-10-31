package com.authplatform.sa.dto;

import com.authplatform.user.entity.PlatformRole;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class SaDtos {
  private SaDtos() {}

  public record LoginRequest(
      @NotBlank @Email String email, @NotBlank String password, String mfaCode) {
    public LoginRequest(String email, String password) {
      this(email, password, null);
    }
  }

  public record LoginResponse(
      @JsonIgnore String accessToken,
      long expiresIn,
      AccountView account,
      @JsonIgnore String refreshToken,
      boolean otpRequired,
      String challengeId,
      String message) {
    public LoginResponse(
        String accessToken, long expiresIn, AccountView account, String refreshToken) {
      this(accessToken, expiresIn, account, refreshToken, false, null, null);
    }
  }

  public record AccountView(
      UUID id,
      String name,
      String email,
      boolean emailVerified,
      PlatformRole platformRole,
      String status,
      Instant createdAt,
      long appCount) {}

  public record AccountDetails(AccountView account, List<AppView> apps) {}

  public record CreateSaRequest(
      @NotBlank @Size(max = 120) String name,
      @NotBlank @Email @Size(max = 320) String email,
      @NotBlank @Size(min = 10, max = 128) String password) {}

  public record UpdateAccountRequest(
      @Size(max = 120) String name,
      String status,
      PlatformRole platformRole,
      @Size(min = 10, max = 128) String password) {}

  public record AppView(
      UUID id,
      String name,
      String publishableKey,
      UUID ownerAccountId,
      String ownerEmail,
      List<String> allowedOrigins,
      boolean requireEmailVerification,
      boolean mfaRequired,
      String status,
      Instant createdAt,
      String secretKeyHint,
      long userCount,
      Integer accessTokenTtlSeconds,
      Integer refreshTokenTtlSeconds) {
    public AppView(
        UUID id,
        String name,
        UUID ownerAccountId,
        String ownerEmail,
        List<String> allowedOrigins,
        boolean requireEmailVerification,
        boolean mfaRequired,
        String status,
        Instant createdAt,
        String secretKeyHint,
        long userCount) {
      this(
          id,
          name,
          null,
          ownerAccountId,
          ownerEmail,
          allowedOrigins,
          requireEmailVerification,
          mfaRequired,
          status,
          createdAt,
          secretKeyHint,
          userCount,
          null,
          null);
    }

    public AppView(
        UUID id,
        String name,
        UUID ownerAccountId,
        String ownerEmail,
        List<String> allowedOrigins,
        boolean requireEmailVerification,
        String status,
        Instant createdAt,
        String secretKeyHint,
        long userCount) {
      this(
          id,
          name,
          null,
          ownerAccountId,
          ownerEmail,
          allowedOrigins,
          requireEmailVerification,
          false,
          status,
          createdAt,
          secretKeyHint,
          userCount,
          null,
          null);
    }
  }

  public record UpdateAppRequest(
      @Size(max = 100) String name,
      @Size(max = 20) List<String> allowedOrigins,
      String verifyEmailUrl,
      String resetPasswordUrl,
      Boolean requireEmailVerification,
      String status,
      Boolean mfaRequired,
      @Min(60) @Max(86_400) Integer accessTokenTtlSeconds,
      @Min(3_600) @Max(7_776_000) Integer refreshTokenTtlSeconds,
      Boolean usePlatformTokenTtls) {
    public UpdateAppRequest(
        String name,
        List<String> allowedOrigins,
        String verifyEmailUrl,
        String resetPasswordUrl,
        Boolean requireEmailVerification,
        String status) {
      this(
          name,
          allowedOrigins,
          verifyEmailUrl,
          resetPasswordUrl,
          requireEmailVerification,
          status,
          null,
          null,
          null,
          null);
    }

    public UpdateAppRequest(
        String name,
        List<String> allowedOrigins,
        String verifyEmailUrl,
        String resetPasswordUrl,
        Boolean requireEmailVerification,
        String status,
        Boolean mfaRequired) {
      this(
          name,
          allowedOrigins,
          verifyEmailUrl,
          resetPasswordUrl,
          requireEmailVerification,
          status,
          mfaRequired,
          null,
          null,
          null);
    }
  }

  public record RotatedSecretResponse(UUID appId, String secretKey, String secretKeyHint) {}

  public record AppUserView(
      UUID id,
      UUID appId,
      String name,
      String email,
      boolean emailVerified,
      String status,
      Instant lastLoginAt,
      Instant createdAt,
      boolean invited) {}

  public record UpdateAppUserRequest(
      @Size(max = 120) String name,
      String status,
      Boolean emailVerified,
      @Size(min = 10, max = 128) String password) {}

  public record AppUserCount(UUID appId, String appName, long userCount) {}

  public record AnalyticsOverview(
      long totalAccounts,
      long activeAccounts,
      long verifiedAccounts,
      long totalApps,
      long activeApps,
      long totalAppUsers,
      long activeAppUsers,
      List<AppUserCount> usersByApp) {}

  public record AuditLogView(
      Long id,
      UUID appId,
      UUID actorAccountId,
      UUID actorAppUserId,
      String actorType,
      String action,
      String ipAddress,
      String requestId,
      Instant createdAt,
      Map<String, Object> metadata) {}

  public record PageResponse<T>(
      List<T> items, int page, int size, long totalItems, int totalPages) {}
}
