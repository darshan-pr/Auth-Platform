package com.authplatform.auth.security;

import com.authplatform.auth.service.JwtService;
import com.authplatform.common.security.AuthenticatedPrincipal;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.common.security.ApiErrorResponses;
import com.authplatform.sa.service.SaAuthService;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
  private static final String CONSOLE_ACCESS_COOKIE = "authplatform_access";
  private static final String SA_ACCESS_COOKIE = "authplatform_sa_access";
  private final JwtService jwt;
  private final StringRedisTemplate redis;
  private final boolean secureCookies;

  public JwtAuthenticationFilter(
      JwtService jwt,
      StringRedisTemplate redis,
      @Value("${authplatform.security.cookie-secure:false}") boolean secureCookies) {
    this.jwt = jwt;
    this.redis = redis;
    this.secureCookies = secureCookies;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return path.startsWith("/api/console/auth/") || path.startsWith("/api/sa/auth/");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String rawToken = bearerToken(request);
    if (rawToken == null) {
      chain.doFilter(request, response);
      return;
    }
    String path = request.getRequestURI();
    UUID appId = null;
    boolean appUser = path.startsWith("/api/v1/");
    boolean sa = path.startsWith("/api/sa/");
    if (appUser) {
      var app =
          (com.authplatform.app.entity.App)
              request.getAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE);
      if (app == null) {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "INVALID_KEY");
        return;
      }
      appId = app.getId();
    }
    String audience =
        sa ? SaAuthService.AUDIENCE : appUser ? appId.toString() : "authplatform-console";
    JWTClaimsSet claims;
    try {
      claims = jwt.parse(rawToken, audience);
    } catch (RuntimeException ex) {
      expireAccessCookie(request, response);
      unauthorized(request, response);
      return;
    }

    String sid;
    UUID subjectId;
    String role;
    try {
      sid = claims.getStringClaim("sid");
      subjectId = UUID.fromString(claims.getSubject());
      role = claims.getStringClaim("role");
      UUID.fromString(sid);
    } catch (Exception ex) {
      expireAccessCookie(request, response);
      unauthorized(request, response);
      return;
    }

    boolean revoked;
    try {
      revoked = Boolean.TRUE.equals(redis.hasKey("authplatform:revoked:sid:" + sid));
    } catch (RuntimeException ex) {
      log.error("Unable to check session revocation for {}", request.getRequestURI(), ex);
      unavailable(request, response);
      return;
    }
    if (revoked) {
      expireAccessCookie(request, response);
      unauthorized(request, response);
      return;
    }

    AuthenticatedPrincipal principal = new AuthenticatedPrincipal(subjectId, appId, sid, appUser);
    String authority = appUser ? "ROLE_USER" : "ROLE_" + (role == null ? "USER" : role);
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                principal, null, java.util.List.of(() -> authority)));
    chain.doFilter(request, response);
  }

  private void unauthorized(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (ApiErrorResponses.isPlatformApi(request)) {
      ApiErrorResponses.write(request, response, ErrorCode.UNAUTHENTICATED);
    } else {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UNAUTHENTICATED");
    }
  }

  private void unavailable(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (ApiErrorResponses.isPlatformApi(request)) {
      ApiErrorResponses.write(request, response, ErrorCode.RATE_LIMIT_UNAVAILABLE);
    } else {
      response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "AUTHENTICATION_UNAVAILABLE");
    }
  }

  private void expireAccessCookie(HttpServletRequest request, HttpServletResponse response) {
    String path = request.getRequestURI();
    String cookieName;
    String cookiePath;
    if (path.startsWith("/api/console/")) {
      cookieName = CONSOLE_ACCESS_COOKIE;
      cookiePath = "/api/console";
    } else if (path.startsWith("/api/sa/")) {
      cookieName = SA_ACCESS_COOKIE;
      cookiePath = "/api/sa";
    } else {
      return;
    }
    ResponseCookie expired =
        ResponseCookie.from(cookieName, "")
            .httpOnly(true)
            .secure(secureCookies)
            .sameSite("Strict")
            .path(cookiePath)
            .maxAge(Duration.ZERO)
            .build();
    response.addHeader(HttpHeaders.SET_COOKIE, expired.toString());
  }

  private String bearerToken(HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    if (header != null && header.startsWith("Bearer ")) return header.substring(7);

    String cookieName =
        request.getRequestURI().startsWith("/api/console/")
            ? CONSOLE_ACCESS_COOKIE
            : request.getRequestURI().startsWith("/api/sa/") ? SA_ACCESS_COOKIE : null;
    if (cookieName == null || request.getCookies() == null) return null;
    return Arrays.stream(request.getCookies())
        .filter(cookie -> cookieName.equals(cookie.getName()))
        .map(jakarta.servlet.http.Cookie::getValue)
        .findFirst()
        .orElse(null);
  }
}
