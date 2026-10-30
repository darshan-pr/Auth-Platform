package com.authplatform.sa.controller;

import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.sa.dto.SaDtos;
import com.authplatform.sa.service.SaAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sa/auth")
public class SaAuthController {
  private final SaAuthService service;
  private final Duration accessTtl;
  private final Duration refreshTtl;
  private final boolean secureCookies;

  public SaAuthController(
      SaAuthService service,
      @Value("${authplatform.jwt.account-access-token-ttl}") Duration accessTtl,
      @Value("${authplatform.jwt.account-refresh-token-ttl}") Duration refreshTtl,
      @Value("${authplatform.security.cookie-secure:false}") boolean secureCookies) {
    this.service = service;
    this.accessTtl = accessTtl;
    this.refreshTtl = refreshTtl;
    this.secureCookies = secureCookies;
  }

  @PostMapping("/login")
  ResponseEntity<?> login(
      @Valid @RequestBody SaDtos.LoginRequest request, HttpServletRequest servlet) {
    SaDtos.LoginResponse result =
        service.login(request, servlet.getRemoteAddr(), servlet.getHeader("User-Agent"));
    if (result.otpRequired()) {
      return noStore(
          ResponseEntity.status(org.springframework.http.HttpStatus.ACCEPTED)
              .header(HttpHeaders.SET_COOKIE, cookie("", false).toString())
              .header(HttpHeaders.SET_COOKIE, accessCookie("", false).toString())
              .body(
                  new com.authplatform.auth.dto.AuthDtos.LoginChallengeResponse(
                      false, true, result.challengeId(), result.expiresIn(), result.message())));
    }
    return sessionResponse(result);
  }

  @PostMapping("/login/otp")
  ResponseEntity<?> verifyOtp(
      @Valid @RequestBody MfaDtos.OtpVerify request, HttpServletRequest servlet) {
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

  @PostMapping("/forgot-password")
  ResponseEntity<MfaDtos.OtpChallenge> forgot(
      @Valid @RequestBody com.authplatform.auth.dto.AuthDtos.ForgotPasswordRequest request) {
    return noStore(ResponseEntity.accepted().body(service.forgot(request.email())));
  }

  @PostMapping("/forgot-password/otp/resend")
  ResponseEntity<MfaDtos.OtpChallenge> resendPasswordResetOtp(
      @Valid @RequestBody MfaDtos.OtpResend request) {
    return noStore(
        ResponseEntity.accepted().body(service.resendPasswordResetOtp(request.challengeId())));
  }

  @PostMapping("/reset-password")
  ResponseEntity<com.authplatform.auth.dto.AuthDtos.MessageResponse> reset(
      @Valid @RequestBody com.authplatform.auth.dto.AuthDtos.OtpPasswordResetRequest request) {
    service.reset(request);
    return noStore(
        ResponseEntity.ok(
            new com.authplatform.auth.dto.AuthDtos.MessageResponse("Password reset successfully")));
  }

  private ResponseEntity<SaDtos.LoginResponse> sessionResponse(SaDtos.LoginResponse result) {
    return noStore(
        ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, cookie(result.refreshToken(), true).toString())
            .header(HttpHeaders.SET_COOKIE, accessCookie(result.accessToken(), true).toString())
            .body(result));
  }

  @PostMapping("/refresh")
  ResponseEntity<SaDtos.LoginResponse> refresh(
      @CookieValue(name = "authplatform_sa_refresh", required = false) String token,
      @RequestHeader(name = "X-Requested-With", required = false) String requested) {
    requireSaHeader(requested);
    if (token == null)
      throw new com.authplatform.common.exception.ApiException(
          com.authplatform.common.exception.ErrorCode.TOKEN_INVALID);
    SaDtos.LoginResponse result = service.refresh(token);
    return noStore(
        ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, cookie(result.refreshToken(), true).toString())
            .header(HttpHeaders.SET_COOKIE, accessCookie(result.accessToken(), true).toString())
            .body(result));
  }

  @PostMapping("/logout")
  ResponseEntity<Void> logout(
      @CookieValue(name = "authplatform_sa_refresh", required = false) String token,
      @RequestHeader(name = "X-Requested-With", required = false) String requested) {
    requireSaHeader(requested);
    if (token != null) service.logout(token);
    return ResponseEntity.noContent()
        .header(HttpHeaders.SET_COOKIE, cookie("", false).toString())
        .header(HttpHeaders.SET_COOKIE, accessCookie("", false).toString())
        .build();
  }

  private void requireSaHeader(String value) {
    if (!"authplatform-sa".equals(value))
      throw new com.authplatform.common.exception.ApiException(
          com.authplatform.common.exception.ErrorCode.ACCESS_DENIED);
  }

  private ResponseCookie cookie(String value, boolean replacement) {
    return ResponseCookie.from("authplatform_sa_refresh", replacement ? value : "")
        .httpOnly(true)
        .secure(secureCookies)
        .sameSite("Strict")
        .path("/api/sa/auth")
        .maxAge(replacement ? refreshTtl : Duration.ZERO)
        .build();
  }

  private ResponseCookie accessCookie(String value, boolean replacement) {
    return ResponseCookie.from("authplatform_sa_access", replacement ? value : "")
        .httpOnly(true)
        .secure(secureCookies)
        .sameSite("Strict")
        .path("/api/sa")
        .maxAge(replacement ? accessTtl : Duration.ZERO)
        .build();
  }

  private <T> ResponseEntity<T> noStore(ResponseEntity<T> response) {
    return ResponseEntity.status(response.getStatusCode())
        .headers(
            headers -> {
              headers.putAll(response.getHeaders());
              headers.setCacheControl("no-store");
            })
        .body(response.getBody());
  }
}
