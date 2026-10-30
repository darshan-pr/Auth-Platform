package com.authplatform.auth.controller;

import com.authplatform.app.entity.App;
import com.authplatform.app.dto.AppDtos;
import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.auth.security.AppKeyAuthenticationFilter;
import com.authplatform.auth.service.AppUserAuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class SdkAuthController {
  private final AppUserAuthService service;

  public SdkAuthController(AppUserAuthService service) {
    this.service = service;
  }

  @GetMapping("/application")
  AppDtos.ApplicationBrandingResponse application(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app) {
    return new AppDtos.ApplicationBrandingResponse(
        app.getName(),
        app.getIconUrl(),
        app.getIconDataUrl(),
        app.getIconPositionX(),
        app.getIconPositionY(),
        app.getIconZoomPercent());
  }

  @PostMapping("/signup")
  ResponseEntity<AuthDtos.UserSummary> signup(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.RegisterRequest request) {
    return ResponseEntity.status(HttpStatus.CREATED).body(service.register(app.getId(), request));
  }

  @PostMapping("/verify-email")
  AuthDtos.VerifyResponse verify(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.TokenRequest request) {
    return service.verify(app.getId(), request.token());
  }

  @PostMapping("/resend-verification")
  ResponseEntity<AuthDtos.MessageResponse> resend(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.ForgotPasswordRequest request) {
    service.resend(app.getId(), request.email());
    return ResponseEntity.status(HttpStatus.ACCEPTED)
        .body(new AuthDtos.MessageResponse("If the account exists, an email has been sent"));
  }

  @PostMapping("/login")
  ResponseEntity<?> login(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.LoginRequest request,
      jakarta.servlet.http.HttpServletRequest servlet) {
    AuthDtos.LoginResponse result =
        service.login(
            app.getId(), request, servlet.getRemoteAddr(), servlet.getHeader("User-Agent"));
    if (result.otpRequired()) {
      return ResponseEntity.status(HttpStatus.ACCEPTED)
          .body(
              new AuthDtos.LoginChallengeResponse(
                  false, true, result.challengeId(), result.expiresIn(), result.message()));
    }
    return ResponseEntity.ok(result);
  }

  @PostMapping("/login/otp")
  ResponseEntity<AuthDtos.LoginResponse> verifyOtp(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody MfaDtos.OtpVerify request,
      jakarta.servlet.http.HttpServletRequest servlet) {
    return ResponseEntity.ok(
        service.verifyOtp(
            app.getId(),
            request.challengeId(),
            request.code(),
            servlet.getRemoteAddr(),
            servlet.getHeader("User-Agent")));
  }

  @PostMapping("/login/otp/resend")
  ResponseEntity<MfaDtos.OtpChallenge> resendLoginOtp(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody MfaDtos.OtpResend request) {
    return ResponseEntity.accepted()
        .body(service.resendLoginOtp(app.getId(), request.challengeId()));
  }

  @PostMapping("/refresh")
  AuthDtos.LoginResponse refresh(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.RefreshRequest request) {
    return service.refresh(app.getId(), request.refreshToken());
  }

  @PostMapping("/logout")
  ResponseEntity<Void> logout(@Valid @RequestBody AuthDtos.RefreshRequest request) {
    service.logout(request.refreshToken());
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/forgot-password")
  ResponseEntity<AuthDtos.MessageResponse> forgot(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.ForgotPasswordRequest request) {
    service.forgot(app.getId(), request.email());
    return ResponseEntity.status(HttpStatus.ACCEPTED)
        .body(new AuthDtos.MessageResponse("If the account exists, an email has been sent"));
  }

  @PostMapping("/forgot-password/otp")
  ResponseEntity<MfaDtos.OtpChallenge> forgotWithOtp(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.ForgotPasswordRequest request) {
    return ResponseEntity.accepted().body(service.forgotWithOtp(app.getId(), request.email()));
  }

  @PostMapping("/forgot-password/otp/resend")
  ResponseEntity<MfaDtos.OtpChallenge> resendPasswordResetOtp(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody MfaDtos.OtpResend request) {
    return ResponseEntity.accepted()
        .body(service.resendPasswordResetOtp(app.getId(), request.challengeId()));
  }

  @PostMapping("/reset-password/otp")
  AuthDtos.MessageResponse resetWithOtp(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.OtpPasswordResetRequest request) {
    service.resetWithOtp(app.getId(), request);
    return new AuthDtos.MessageResponse("Password reset successfully");
  }

  @PostMapping("/reset-password")
  AuthDtos.MessageResponse reset(
      @RequestAttribute(AppKeyAuthenticationFilter.APP_ATTRIBUTE) App app,
      @Valid @RequestBody AuthDtos.ResetPasswordRequest request) {
    service.reset(app.getId(), request);
    return new AuthDtos.MessageResponse("Password reset successfully");
  }
}
