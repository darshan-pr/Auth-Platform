package com.authplatform.app.dto;

import com.authplatform.role.dto.RoleDtos;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class AppDtos {
  private AppDtos() {}

  public record CreateAppRequest(
      @NotBlank @Size(max = 100) String name,
      @Size(max = 20) List<String> allowedOrigins,
      String verifyEmailUrl,
      String resetPasswordUrl,
      Boolean mfaRequired,
      @Min(60) @Max(86_400) Integer accessTokenTtlSeconds,
      @Min(3_600) @Max(7_776_000) Integer refreshTokenTtlSeconds) {
    public CreateAppRequest(
        String name,
        List<String> allowedOrigins,
        String verifyEmailUrl,
        String resetPasswordUrl,
        Boolean mfaRequired) {
      this(name, allowedOrigins, verifyEmailUrl, resetPasswordUrl, mfaRequired, null, null);
    }

    public CreateAppRequest(
        String name, List<String> allowedOrigins, String verifyEmailUrl, String resetPasswordUrl) {
      this(name, allowedOrigins, verifyEmailUrl, resetPasswordUrl, false, null, null);
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
      Boolean usePlatformTokenTtls,
      @Size(max = 2048) String iconUrl,
      @Size(max = 500_000) String iconDataUrl,
      @Min(0) @Max(100) Integer iconPositionX,
      @Min(0) @Max(100) Integer iconPositionY,
      @Min(100) @Max(300) Integer iconZoomPercent) {
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
          null,
          null,
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
          null,
          null,
          null,
          null,
          null,
          null);
    }
  }

  public record RoleSummary(UUID id, String name) {}

  public record AppResponse(
      UUID id,
      String name,
      String publishableKey,
      List<String> allowedOrigins,
      String verifyEmailUrl,
      boolean requireEmailVerification,
      boolean mfaRequired,
      String status,
      Instant createdAt,
      String secretKeyHint,
      RoleSummary defaultRole,
      Integer accessTokenTtlSeconds,
      Integer refreshTokenTtlSeconds,
      String iconUrl,
      String iconDataUrl,
      int iconPositionX,
      int iconPositionY,
      int iconZoomPercent) {}

  public record ApplicationBrandingResponse(
      String name,
      String iconUrl,
      String iconDataUrl,
      int iconPositionX,
      int iconPositionY,
      int iconZoomPercent) {}

  public record AppMfaStatus(boolean required, boolean enabled, boolean setupRequired) {}

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

  public record InviteeRequest(
      @jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(max = 320)
          String email,
      @jakarta.validation.constraints.Size(max = 120) String name) {}

  public record InviteUsersRequest(
      @jakarta.validation.constraints.NotEmpty
          @jakarta.validation.constraints.Size(max = 50)
          List<@jakarta.validation.Valid InviteeRequest> users) {}

  /** outcome is one of INVITED, ALREADY_EXISTS, DUPLICATE or INVALID. */
  public record InviteResult(String email, String outcome, String message) {}

  public record InviteUsersResponse(
      int requested, int invited, int skipped, List<InviteResult> results) {}

  public record AppUserDetailsView(
      AppUserView user,
      List<RoleDtos.RoleView> roles,
      List<RoleDtos.UserRolePermissionsView> userRolePermissions,
      List<String> permissions) {}

  public record UpdateAppUserRequest(
      @Size(max = 120) String name,
      String status,
      Boolean emailVerified,
      @Size(min = 10, max = 128) String password) {}

  public record AppCreatedResponse(
      UUID id,
      String name,
      String publishableKey,
      String secretKey,
      List<String> allowedOrigins,
      String verifyEmailUrl,
      boolean requireEmailVerification,
      boolean mfaRequired,
      String status,
      Instant createdAt,
      RoleSummary defaultRole,
      Integer accessTokenTtlSeconds,
      Integer refreshTokenTtlSeconds,
      String iconUrl,
      String iconDataUrl,
      int iconPositionX,
      int iconPositionY,
      int iconZoomPercent) {}

  public record RotatedSecretResponse(UUID appId, String secretKey, String secretKeyHint) {}
}
