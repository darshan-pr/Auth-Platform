package com.authplatform.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public final class MfaDtos {
  private MfaDtos() {}

  public record Status(boolean required, boolean enabled, boolean setupRequired) {}

  public record OtpChallenge(String challengeId, long expiresIn, String message) {}

  public record OtpResend(@NotBlank String challengeId) {}

  public record OtpVerify(
      @NotBlank String challengeId,
      @Pattern(regexp = "\\d{6}", message = "Code must be 6 digits") String code) {}
}
