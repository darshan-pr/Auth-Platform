package com.authplatform.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.authplatform.auth.service.JwtService;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.Cookie;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class JwtAuthenticationFilterTest {
  @Test
  void staleConsoleAccessCookieDoesNotBlockLogin() throws Exception {
    JwtService jwt = mock(JwtService.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwt, redis, false);
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/console/auth/login");
    request.setCookies(new Cookie("authplatform_access", "stale"));
    MockHttpServletResponse response = new MockHttpServletResponse();
    MockFilterChain chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    verifyNoInteractions(jwt, redis);
    assertThat(chain.getRequest()).isSameAs(request);
  }

  @Test
  void invalidConsoleAccessCookieIsExpiredWithoutClearingRefreshCookie() throws Exception {
    JwtService jwt = mock(JwtService.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    when(jwt.parse("stale", "authplatform-console"))
        .thenThrow(new ApiException(ErrorCode.UNAUTHENTICATED));
    JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwt, redis, false);
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/console/me");
    request.setCookies(new Cookie("authplatform_access", "stale"));
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilter(request, response, new MockFilterChain());

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getErrorMessage()).isNull();
    assertThat(response.getContentAsString()).contains("\"code\":\"UNAUTHENTICATED\"");
    assertThat(response.getHeader("Set-Cookie"))
        .contains("authplatform_access=")
        .contains("Path=/api/console")
        .contains("Max-Age=0")
        .doesNotContain("authplatform_refresh");
    verifyNoInteractions(redis);
  }

  @Test
  void redisUnavailableDoesNotExpireTheAccessCookie() throws Exception {
    String sid = UUID.randomUUID().toString();
    JwtService jwt = mock(JwtService.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    when(jwt.parse("valid", "authplatform-console"))
        .thenReturn(
            new JWTClaimsSet.Builder()
                .subject(UUID.randomUUID().toString())
                .claim("sid", sid)
                .claim("role", "USER")
                .build());
    when(redis.hasKey("authplatform:revoked:sid:" + sid))
        .thenThrow(new IllegalStateException("Redis unavailable"));
    JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwt, redis, false);
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/console/me");
    request.setCookies(new Cookie("authplatform_access", "valid"));
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilter(request, response, new MockFilterChain());

    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(response.getHeader("Set-Cookie")).isNull();
  }
}
