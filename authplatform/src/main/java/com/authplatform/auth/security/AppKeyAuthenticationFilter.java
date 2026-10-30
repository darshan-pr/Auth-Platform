package com.authplatform.auth.security;

import com.authplatform.app.entity.App;
import com.authplatform.app.service.AppService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AppKeyAuthenticationFilter extends OncePerRequestFilter {
  public static final String APP_ATTRIBUTE = "authplatform.app";
  private final AppService apps;

  public AppKeyAuthenticationFilter(AppService apps) {
    this.apps = apps;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (!request.getRequestURI().startsWith("/api/v1/")) {
      chain.doFilter(request, response);
      return;
    }
    if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
      chain.doFilter(request, response);
      return;
    }
    String key = request.getHeader("X-authplatform-Key");
    if (key == null || key.isBlank()) {
      response.sendError(401, "INVALID_KEY");
      return;
    }
    try {
      App app = apps.findByPublishableKey(key);
      if (!"ACTIVE".equals(app.getStatus())) {
        response.sendError(403, "APP_SUSPENDED");
        return;
      }
      request.setAttribute(APP_ATTRIBUTE, app);
      chain.doFilter(request, response);
    } catch (RuntimeException ex) {
      response.sendError(401, "INVALID_KEY");
    }
  }
}
