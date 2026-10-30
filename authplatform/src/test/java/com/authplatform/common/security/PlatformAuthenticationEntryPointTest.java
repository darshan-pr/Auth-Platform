package com.authplatform.common.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;

class PlatformAuthenticationEntryPointTest {
  private final PlatformAuthenticationEntryPoint entryPoint = new PlatformAuthenticationEntryPoint();

  @Test
  void missingConsoleAccessTokenReturnsAJsonUnauthorizedSoClientsCanRefresh() throws Exception {
    assertUnauthorized("/api/console/me");
  }

  @Test
  void missingSaAccessTokenReturnsAJsonUnauthorizedSoClientsCanRefresh() throws Exception {
    assertUnauthorized("/api/sa/analytics/overview");
  }

  @Test
  void otherApisKeepTheirExistingForbiddenResponse() throws Exception {
    MockHttpServletResponse response = new MockHttpServletResponse();

    entryPoint.commence(
        new MockHttpServletRequest("GET", "/api/v1/users/me"),
        response,
        new InsufficientAuthenticationException("missing"));

    assertThat(response.getStatus()).isEqualTo(403);
  }

  private void assertUnauthorized(String path) throws Exception {
    MockHttpServletResponse response = new MockHttpServletResponse();

    entryPoint.commence(
        new MockHttpServletRequest("GET", path),
        response,
        new InsufficientAuthenticationException("missing"));

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getErrorMessage()).isNull();
    assertThat(response.getContentType()).startsWith("application/json");
    assertThat(response.getContentAsString()).contains("\"code\":\"UNAUTHENTICATED\"");
  }
}
