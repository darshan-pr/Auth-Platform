package com.authplatform.auth.controller;

import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.auth.service.AccountAuthService;
import jakarta.validation.Valid;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/console/auth")
public class ConsoleAuthController {
  private final AccountAuthService service;
  private final Duration accessTtl;
  private final Duration refreshTtl;
  private final boolean secureCookies;

  public ConsoleAuthController(
      AccountAuthService service,
      @Value("${authplatform.jwt.account-access-token-ttl}") Duration accessTtl,
      @Value("${authplatform.jwt.account-refresh-token-ttl}") Duration refreshTtl,
      @Value("${authplatform.security.cookie-secure:false}") boolean secureCookies) {
    this.service = service;
    this.accessTtl = accessTtl;
    this.refreshTtl = refreshTtl;
    this.secureCookies = secureCookies;
  }

  @PostMapping("/signup")
  ResponseEntity<AuthDtos.SignupResponse> signup(
      @Valid @RequestBody AuthDtos.RegisterRequest request) {
    return noStore(ResponseEntity.status(HttpStatus.CREATED).body(service.register(request)));
  }

  @PostMapping("/verify-email")
  ResponseEntity<AuthDtos.VerifyResponse> verify(
      @Valid @RequestBody AuthDtos.TokenRequest request) {
    return noStore(ResponseEntity.ok(service.verify(request.token())));
  }

  // Links in emails sent before the console verification page existed. Scanners prefetch email
  // links, so hand off to the page instead of consuming the single-use token on a GET.
  @GetMapping("/verify-email")
  ResponseEntity<Void> verifyFromEmailLink(@RequestParam String token) {
    return ResponseEntity.status(HttpStatus.FOUND)
        .location(
            java.net.URI.create(
                "/verify-email?token="
                    + java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8)))
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .build();
  }

  @PostMapping("/resend-verification")
  ResponseEntity<AuthDtos.MessageResponse> resend(
      @Valid @RequestBody AuthDtos.ForgotPasswordRequest request) {
    service.resend(request.email());
    return noStore(
        ResponseEntity.status(HttpStatus.ACCEPTED)
            .body(new AuthDtos.MessageResponse("If the account exists, an email has been sent")));
  }

  @PostMapping("/login")
  ResponseEntity<?> login(
      @Valid @RequestBody AuthDtos.LoginRequest request,
      jakarta.servlet.http.HttpServletRequest servlet) {
    AuthDtos.ConsoleLoginResult result =
        service.login(request, servlet.getRemoteAddr(), servlet.getHeader("User-Agent"));
    if (result.otpRequired()) {
      return noStore(
          ResponseEntity.status(HttpStatus.ACCEPTED)
              .header(HttpHeaders.SET_COOKIE, cookie("", false).toString())
              .header(HttpHeaders.SET_COOKIE, accessCookie("", false).toString())
              .body(
                  new AuthDtos.LoginChallengeResponse(
                      false, true, result.challengeId(), result.expiresIn(), result.message())));
    }
    return sessionResponse(result);
  }

  @PostMapping("/login/otp")
  ResponseEntity<?> verifyOtp(
      @Valid @RequestBody MfaDtos.OtpVerify request,
      jakarta.servlet.http.HttpServletRequest servlet) {
    return sessionResponse(
        service.verifyOtp(
            request.challengeId(),
            request.code(),
            servlet.getRemoteAddr(),
            servlet.getHeader("User-Agent")));
  }

  @PostMapping("/login/otp/resend")
  ResponseEntity<MfaDtos.OtpChallenge> resendLoginOtp(
      @Valid @RequestBody MfaDtos.OtpResend request) {
    return noStore(ResponseEntity.accepted().body(service.resendLoginOtp(request.challengeId())));
  }

  private ResponseEntity<AuthDtos.ConsoleLoginResult> sessionResponse(
      AuthDtos.ConsoleLoginResult result) {
    return noStore(
        ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, cookie(result.refreshToken(), true).toString())
            .header(HttpHeaders.SET_COOKIE, accessCookie(result.accessToken(), true).toString())
            .body(result));
  }

  @PostMapping("/refresh")
  ResponseEntity<AuthDtos.ConsoleRefreshResult> refresh(
      @CookieValue(name = "authplatform_refresh", required = false) String token,
      @RequestHeader(name = "X-Requested-With", required = false) String requested) {
    requireConsoleHeader(requested);
    if (token == null)
      throw new com.authplatform.common.exception.ApiException(
          com.authplatform.common.exception.ErrorCode.TOKEN_INVALID);
    AuthDtos.ConsoleRefreshResult result = service.refresh(token);
    return noStore(
        ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, cookie(result.refreshToken(), true).toString())
            .header(HttpHeaders.SET_COOKIE, accessCookie(result.accessToken(), true).toString())
            .body(result));
  }

  @PostMapping("/logout")
  ResponseEntity<Void> logout(
      @CookieValue(name = "authplatform_refresh", required = false) String token,
      @RequestHeader(name = "X-Requested-With", required = false) String requested) {
    requireConsoleHeader(requested);
    if (token != null) service.logout(token);
    return ResponseEntity.noContent()
        .header(HttpHeaders.SET_COOKIE, cookie("", false).toString())
        .header(HttpHeaders.SET_COOKIE, accessCookie("", false).toString())
        .build();
  }

  @PostMapping("/forgot-password")
  ResponseEntity<MfaDtos.OtpChallenge> forgot(
      @Valid @RequestBody AuthDtos.ForgotPasswordRequest request) {
    return noStore(
        ResponseEntity.status(HttpStatus.ACCEPTED).body(service.forgot(request.email())));
  }

  @PostMapping("/forgot-password/otp/resend")
  ResponseEntity<MfaDtos.OtpChallenge> resendPasswordResetOtp(
      @Valid @RequestBody MfaDtos.OtpResend request) {
    return noStore(
        ResponseEntity.accepted().body(service.resendPasswordResetOtp(request.challengeId())));
  }

  @PostMapping("/reset-password")
  ResponseEntity<AuthDtos.MessageResponse> reset(
      @Valid @RequestBody AuthDtos.OtpPasswordResetRequest request) {
    service.reset(request);
    return noStore(ResponseEntity.ok(new AuthDtos.MessageResponse("Password reset successfully")));
  }

  private ResponseCookie cookie(String value, boolean replacement) {
    return ResponseCookie.from("authplatform_refresh", replacement ? value : "")
        .httpOnly(true)
        .secure(secureCookies)
        .sameSite("Strict")
        .path("/api/console/auth")
        .maxAge(replacement ? refreshTtl : Duration.ZERO)
        .build();
  }

  private ResponseCookie accessCookie(String value, boolean replacement) {
    return ResponseCookie.from("authplatform_access", replacement ? value : "")
        .httpOnly(true)
        .secure(secureCookies)
        .sameSite("Strict")
        .path("/api/console")
        .maxAge(replacement ? accessTtl : Duration.ZERO)
        .build();
  }

  private void requireConsoleHeader(String value) {
    if (!"authplatform-console".equals(value))
      throw new com.authplatform.common.exception.ApiException(
          com.authplatform.common.exception.ErrorCode.ACCESS_DENIED);
  }

  private <T> ResponseEntity<T> noStore(ResponseEntity<T> response) {
    return ResponseEntity.status(response.getStatusCode())
        .headers(
            h -> {
              h.putAll(response.getHeaders());
              h.setCacheControl("no-store");
            })
        .body(response.getBody());
  }
}
