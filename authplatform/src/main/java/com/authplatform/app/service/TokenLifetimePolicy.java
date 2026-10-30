package com.authplatform.app.service;

import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;

public final class TokenLifetimePolicy {
  public static final int MIN_ACCESS_TTL_SECONDS = 60;
  public static final int MAX_ACCESS_TTL_SECONDS = 86_400;
  public static final int MIN_REFRESH_TTL_SECONDS = 3_600;
  public static final int MAX_REFRESH_TTL_SECONDS = 7_776_000;

  private TokenLifetimePolicy() {}

  public static void validatePair(Integer accessTtlSeconds, Integer refreshTtlSeconds) {
    if ((accessTtlSeconds == null) != (refreshTtlSeconds == null)) {
      throw invalid("Both access and refresh token lifetimes must be configured together");
    }
    if (accessTtlSeconds == null) return;
    if (accessTtlSeconds < MIN_ACCESS_TTL_SECONDS
        || accessTtlSeconds > MAX_ACCESS_TTL_SECONDS
        || refreshTtlSeconds < MIN_REFRESH_TTL_SECONDS
        || refreshTtlSeconds > MAX_REFRESH_TTL_SECONDS
        || refreshTtlSeconds < accessTtlSeconds) {
      throw invalid(
          "Access lifetime must be 60-86400 seconds; refresh lifetime must be 3600-7776000 seconds and no shorter than access");
    }
  }

  public static void validateUpdate(
      Integer accessTtlSeconds,
      Integer refreshTtlSeconds,
      Boolean usePlatformTokenTtls) {
    if (Boolean.TRUE.equals(usePlatformTokenTtls)) {
      if (accessTtlSeconds != null || refreshTtlSeconds != null) {
        throw invalid("Platform-default lifetimes cannot be combined with custom lifetimes");
      }
      return;
    }
    validatePair(accessTtlSeconds, refreshTtlSeconds);
  }

  private static ApiException invalid(String message) {
    return new ApiException(ErrorCode.VALIDATION_FAILED, message);
  }
}
