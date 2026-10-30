package com.authplatform.ratelimit;

import com.authplatform.common.exception.ErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RateLimitFilter extends OncePerRequestFilter {
  private static final DefaultRedisScript<Long> SLIDING_WINDOW =
      new DefaultRedisScript<>(
          "local now=tonumber(ARGV[1]); local window=tonumber(ARGV[2]); "
              + "local limit=tonumber(ARGV[3]); redis.call('ZREMRANGEBYSCORE',KEYS[1],0,now-window); "
              + "local count=redis.call('ZCARD',KEYS[1]); if count >= limit then return 0 end; "
              + "redis.call('ZADD',KEYS[1],now,ARGV[4]); redis.call('EXPIRE',KEYS[1],math.ceil(window/1000)); return 1",
          Long.class);
  private final StringRedisTemplate redis;
  private final boolean enabled;
  private final int loginCapacity;
  private final Duration loginPeriod;
  private final int signupCapacity;
  private final Duration signupPeriod;
  private final int globalCapacity;
  private final Duration globalPeriod;

  public RateLimitFilter(
      StringRedisTemplate redis,
      @Value("${authplatform.rate-limit.enabled}") boolean enabled,
      @Value("${authplatform.rate-limit.login-capacity}") int loginCapacity,
      @Value("${authplatform.rate-limit.login-period}") Duration loginPeriod,
      @Value("${authplatform.rate-limit.signup-capacity}") int signupCapacity,
      @Value("${authplatform.rate-limit.signup-period}") Duration signupPeriod,
      @Value("${authplatform.rate-limit.global-capacity}") int globalCapacity,
      @Value("${authplatform.rate-limit.global-period}") Duration globalPeriod) {
    this.redis = redis;
    this.enabled = enabled;
    this.loginCapacity = loginCapacity;
    this.loginPeriod = loginPeriod;
    this.signupCapacity = signupCapacity;
    this.signupPeriod = signupPeriod;
    this.globalCapacity = globalCapacity;
    this.globalPeriod = globalPeriod;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    Limit limit = limitFor(request);
    Decision decision =
        !enabled || limit == null
            ? Decision.ALLOWED
            : consume(request.getRemoteAddr(), request.getRequestURI(), limit);
    if (decision == Decision.ALLOWED) {
      chain.doFilter(request, response);
      return;
    }
    if (decision == Decision.UNAVAILABLE) {
      response.setStatus(ErrorCode.RATE_LIMIT_UNAVAILABLE.status().value());
      response.setHeader("Retry-After", "5");
      response.setContentType("application/json");
      response
          .getWriter()
          .write(
              "{\"error\":{\"code\":\"RATE_LIMIT_UNAVAILABLE\",\"message\":\"Authentication protection is temporarily unavailable\"}}");
      return;
    }
    response.setStatus(429);
    response.setHeader("Retry-After", String.valueOf(limit.period().toSeconds()));
    response.setHeader("X-RateLimit-Limit", String.valueOf(limit.capacity()));
    response.setHeader("X-RateLimit-Remaining", "0");
    response.setContentType("application/json");
    response
        .getWriter()
        .write("{\"error\":{\"code\":\"RATE_LIMITED\",\"message\":\"Too many requests\"}}");
  }

  private Decision consume(String ip, String path, Limit limit) {
    try {
      long now = System.currentTimeMillis();
      String key = "authplatform:rl:ip:" + ip + ":" + path;
      Long allowed =
          redis.execute(
              SLIDING_WINDOW,
              List.of(key),
              String.valueOf(now),
              String.valueOf(limit.period().toMillis()),
              String.valueOf(limit.capacity()),
              String.valueOf(now) + ":" + java.util.UUID.randomUUID());
      return Long.valueOf(1).equals(allowed) ? Decision.ALLOWED : Decision.LIMITED;
    } catch (Exception ex) {
      return Decision.UNAVAILABLE;
    }
  }

  private Limit limitFor(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) return null;
    String path = request.getRequestURI();
    if (path.endsWith("/auth/login")
        || path.endsWith("/auth/login/otp")
        || path.endsWith("/auth/login/otp/resend")) return new Limit(loginCapacity, loginPeriod);
    if (path.endsWith("/auth/signup")) return new Limit(signupCapacity, signupPeriod);
    if (path.endsWith("/auth/forgot-password")
        || path.endsWith("/auth/forgot-password/otp")
        || path.endsWith("/auth/forgot-password/otp/resend")
        || path.endsWith("/auth/resend-verification")
        || path.endsWith("/auth/reset-password")
        || path.endsWith("/auth/reset-password/otp"))
      return new Limit(globalCapacity, globalPeriod);
    return null;
  }

  private record Limit(int capacity, Duration period) {}

  private enum Decision {
    ALLOWED,
    LIMITED,
    UNAVAILABLE
  }
}
