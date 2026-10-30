package com.authplatform.sa.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.sa.dto.SaDtos;
import com.authplatform.sa.service.SaAuthService;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

class SaAuthControllerTest {
  @Test
  void otpLoginSetsBothAccountSessionCookiesWithConfiguredLifetimes() {
    SaAuthService service = mock(SaAuthService.class);
    when(service.verifyOtp("challenge-id", "123456", "127.0.0.1", "test-agent"))
        .thenReturn(new SaDtos.LoginResponse("access-token", 1_800, null, "refresh-token"));
    SaAuthController controller =
        new SaAuthController(service, Duration.ofMinutes(30), Duration.ofHours(48), false);
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRemoteAddr("127.0.0.1");
    request.addHeader("User-Agent", "test-agent");

    var response =
        controller.verifyOtp(new MfaDtos.OtpVerify("challenge-id", "123456"), request);
    List<String> cookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);

    assertThat(cookies).hasSize(2);
    assertThat(cookies)
        .anySatisfy(
            cookie ->
                assertThat(cookie)
                    .contains(
                        "authplatform_sa_refresh=refresh-token",
                        "Path=/api/sa/auth",
                        "Max-Age=172800"));
    assertThat(cookies)
        .anySatisfy(
            cookie ->
                assertThat(cookie)
                    .contains(
                        "authplatform_sa_access=access-token",
                        "Path=/api/sa",
                        "Max-Age=1800"));
  }
}
