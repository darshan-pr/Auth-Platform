package com.authplatform.common.security;

import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import java.net.URI;

public final class RedirectUrlValidator {
  private RedirectUrlValidator() {}

  public static String validate(String value) {
    if (value == null || value.isBlank()) return null;
    try {
      URI uri = URI.create(value.trim());
      String scheme = uri.getScheme();
      String host = uri.getHost();
      boolean local = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
      boolean secure = "https".equalsIgnoreCase(scheme);
      boolean localHttp = "http".equalsIgnoreCase(scheme) && local;
      if ((!secure && !localHttp)
          || host == null
          || uri.getUserInfo() != null
          || uri.getFragment() != null
          || uri.getQuery() != null) throw new IllegalArgumentException();
      return uri.toString();
    } catch (Exception ex) {
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED,
          "Verification and reset URLs must be HTTPS URLs without query, fragment, or user-info");
    }
  }
}
