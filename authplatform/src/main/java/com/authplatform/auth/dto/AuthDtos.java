package com.authplatform.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;

public final class AuthDtos {
  private AuthDtos() {}

  public record RegisterRequest(
      @NotBlank @Size(max = 120) String name,
      @NotBlank @Email @Size(max = 320) String email,
      @NotBlank @Size(min = 10, max = 128) String password) {}

  public record LoginRequest(
      @NotBlank @Email String email, @NotBlank String password, String mfaCode) {
    public LoginRequest(String email, String password) {
      this(email, password, null);
    }
  }

  public record RefreshRequest(@NotBlank String refreshToken) {}

  public record TokenRequest(@NotBlank String token) {}

  public record ForgotPasswordRequest(@NotBlank @Email String email) {}

  public record ResetPasswordRequest(
      @NotBlank String token, @NotBlank @Size(min = 10, max = 128) String newPassword) {}

  public record OtpPasswordResetRequest(
      @NotBlank String challengeId,
      @NotBlank
          @jakarta.validation.constraints.Pattern(
              regexp = "\\d{6}",
              message = "Code must be 6 digits")
          String code,
      @NotBlank @Size(min = 10, max = 128) String newPassword) {}

  public record MessageResponse(String message) {}

  public record SignupResponse(UUID id, String email, boolean emailVerified, String message) {}

  public record UserSummary(
      UUID id,
      String name,
      String email,
      boolean emailVerified,
      List<String> roles,
      List<String> permissions) {}

  public record AccountSummary(UUID id, String name, String email, String platformRole) {}

  public record LoginChallengeResponse(
      boolean authenticated,
      boolean otpRequired,
      String challengeId,
      long expiresIn,
      String message) {}

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record LoginResponse(
      String accessToken,
      String refreshToken,
      long expiresIn,
      Long refreshExpiresIn,
      UserSummary user,
      AccountSummary account,
      boolean otpRequired,
      String challengeId,
      String message) {
    public LoginResponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        UserSummary user,
        AccountSummary account) {
      this(accessToken, refreshToken, expiresIn, null, user, account, false, null, null);
    }

    public LoginResponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        UserSummary user,
        AccountSummary account,
        long refreshExpiresIn) {
      this(
          accessToken,
          refreshToken,
          expiresIn,
          refreshExpiresIn,
          user,
          account,
          false,
          null,
          null);
    }

    public LoginResponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        UserSummary user,
        AccountSummary account,
        boolean otpRequired,
        String challengeId,
        String message) {
      this(
          accessToken,
          refreshToken,
          expiresIn,
          null,
          user,
          account,
          otpRequired,
          challengeId,
          message);
    }
  }

  public record ConsoleLoginResult(
      @JsonIgnore String accessToken,
      long expiresIn,
      AccountSummary account,
      @JsonIgnore String refreshToken,
      boolean otpRequired,
      String challengeId,
      String message) {
    public ConsoleLoginResult(
        String accessToken, long expiresIn, AccountSummary account, String refreshToken) {
      this(accessToken, expiresIn, account, refreshToken, false, null, null);
    }
  }

  public record AccessResponse(String accessToken, long expiresIn) {}

  public record ConsoleRefreshResult(
      @JsonIgnore String accessToken, long expiresIn, @JsonIgnore String refreshToken) {}

  public record VerifyResponse(boolean emailVerified) {}
}
