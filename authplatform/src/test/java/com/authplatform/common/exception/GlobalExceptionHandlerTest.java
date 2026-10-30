package com.authplatform.common.exception;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

class GlobalExceptionHandlerTest {
  private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

  @Test
  void logoutErrorsExpireConsoleCookies() {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/console/auth/logout");

    var response = handler.handle(new ApiException(ErrorCode.INTERNAL_ERROR), request);

    assertThat(response.getStatusCode().value()).isEqualTo(500);
    assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE))
        .hasSize(2)
        .anySatisfy(
            cookie -> assertThat(cookie).contains("authplatform_refresh=").contains("Max-Age=0"))
        .anySatisfy(
            cookie -> assertThat(cookie).contains("authplatform_access=").contains("Max-Age=0"));
  }

  @Test
  void invalidRefreshExpiresSaCookies() {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/sa/auth/refresh");

    var response = handler.handle(new ApiException(ErrorCode.TOKEN_INVALID), request);

    assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE))
        .hasSize(2)
        .anySatisfy(
            cookie ->
                assertThat(cookie)
                    .contains("authplatform_sa_refresh=")
                    .contains("Path=/api/sa/auth"))
        .anySatisfy(
            cookie ->
                assertThat(cookie).contains("authplatform_sa_access=")                .contains("Path=/api/sa"));
  }

  @Test
  void refreshInProgressPreservesSaCookies() {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/sa/auth/refresh");

    var response = handler.handle(new ApiException(ErrorCode.REFRESH_IN_PROGRESS), request);

    assertThat(response.getStatusCode().value()).isEqualTo(409);
    assertThat(response.getHeaders().containsKey(HttpHeaders.SET_COOKIE)).isFalse();
  }

  @Test
  void unrelatedErrorsDoNotExpireSessionCookies() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/console/me");

    var response = handler.handle(new ApiException(ErrorCode.UNAUTHENTICATED), request);

    assertThat(response.getHeaders().containsKey(HttpHeaders.SET_COOKIE)).isFalse();
  }
}
