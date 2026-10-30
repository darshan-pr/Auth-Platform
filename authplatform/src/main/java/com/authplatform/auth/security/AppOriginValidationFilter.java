package com.authplatform.auth.security;

import com.authplatform.app.entity.App;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AppOriginValidationFilter extends OncePerRequestFilter {
  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (!request.getRequestURI().startsWith("/api/v1/")
        || "OPTIONS".equalsIgnoreCase(request.getMethod())) {
      chain.doFilter(request, response);
      return;
    }
    App app = (App) request.getAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE);
    String origin = request.getHeader("Origin");
    if (app != null
        && origin != null
        && !origin.isBlank()
        && !app.getAllowedOrigins().contains(origin)) {
      response.sendError(403, "ORIGIN_NOT_ALLOWED");
      return;
    }
    if (origin != null && !origin.isBlank()) {
      response.setHeader("Access-Control-Allow-Origin", origin);
      response.setHeader("Vary", "Origin");
    }
    chain.doFilter(request, response);
  }
}
