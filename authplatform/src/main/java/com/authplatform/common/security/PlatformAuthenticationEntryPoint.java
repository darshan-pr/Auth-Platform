package com.authplatform.common.security;

import com.authplatform.common.exception.ErrorCode;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

/** Returns 401 for unauthenticated console/SA requests so clients know to refresh. */
public class PlatformAuthenticationEntryPoint implements AuthenticationEntryPoint {
  private final AuthenticationEntryPoint fallback = new HttpStatusEntryPoint(HttpStatus.FORBIDDEN);

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException, ServletException {
    if (ApiErrorResponses.isPlatformApi(request)) {
      ApiErrorResponses.write(request, response, ErrorCode.UNAUTHENTICATED);
      return;
    }
    fallback.commence(request, response, authException);
  }
}
