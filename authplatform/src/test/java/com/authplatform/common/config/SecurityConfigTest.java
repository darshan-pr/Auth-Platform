package com.authplatform.common.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.DefaultCorsProcessor;

class SecurityConfigTest {
  @Test
  void allowsConsolePutPreflightForUserPermissionUpdates() throws Exception {
    SecurityConfig security = new SecurityConfig();
    ReflectionTestUtils.setField(security, "consoleAllowedOrigins", "http://localhost:3000");

    MockHttpServletRequest request =
        new MockHttpServletRequest(
            HttpMethod.OPTIONS.name(),
            "/api/console/apps/app/users/user/roles/role/permissions/permission");
    request.addHeader(HttpHeaders.ORIGIN, "http://localhost:3000");
    request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.PUT.name());
    request.addHeader(
        HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,
        "content-type,x-requested-with,x-xsrf-token");

    CorsConfiguration configuration =
        security.corsConfigurationSource().getCorsConfiguration(request);
    MockHttpServletResponse response = new MockHttpServletResponse();

    assertThat(configuration).isNotNull();
    assertThat(new DefaultCorsProcessor().processRequest(configuration, request, response)).isTrue();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).contains("PUT");
  }
}
