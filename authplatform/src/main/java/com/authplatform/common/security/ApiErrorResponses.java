package com.authplatform.common.security;

import com.authplatform.common.dto.ApiError;
import com.authplatform.common.exception.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Writes JSON errors straight to the response. {@code HttpServletResponse.sendError} triggers an
 * {@code /error} dispatch that Spring Security denies, which turns every 401 into a 403 and stops
 * browser clients from refreshing an expired access token.
 */
public final class ApiErrorResponses {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private ApiErrorResponses() {}

  public static boolean isPlatformApi(HttpServletRequest request) {
    String path = request.getRequestURI();
    return path.startsWith("/api/console/") || path.startsWith("/api/sa/");
  }

  public static void write(
      HttpServletRequest request, HttpServletResponse response, ErrorCode code)
      throws IOException {
    Object requestId = request.getAttribute("requestId");
    ApiError body =
        new ApiError(
            new ApiError.Error(
                code.name(),
                code.message(),
                requestId == null ? null : requestId.toString(),
                List.of()));
    response.setStatus(code.status().value());
    response.setHeader("Cache-Control", "no-store");
    response.setContentType("application/json");
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.getWriter().write(MAPPER.writeValueAsString(body));
  }
}
