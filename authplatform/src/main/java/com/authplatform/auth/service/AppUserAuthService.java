package com.authplatform.auth.service;

import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.user.entity.AppUser;
import java.util.UUID;

public interface AppUserAuthService {
  AuthDtos.UserSummary register(UUID appId, AuthDtos.RegisterRequest request);

  AuthDtos.VerifyResponse verify(UUID appId, String token);

  void resend(UUID appId, String email);

  AuthDtos.LoginResponse login(UUID appId, AuthDtos.LoginRequest request, String ip, String agent);

  AuthDtos.LoginResponse verifyOtp(
      UUID appId, String challengeId, String code, String ip, String agent);

  MfaDtos.OtpChallenge resendLoginOtp(UUID appId, String challengeId);

  AuthDtos.LoginResponse refresh(UUID appId, String refreshToken);

  void logout(String refreshToken);

  void forgot(UUID appId, String email);

  void reset(UUID appId, AuthDtos.ResetPasswordRequest request);

  MfaDtos.OtpChallenge forgotWithOtp(UUID appId, String email);

  MfaDtos.OtpChallenge resendPasswordResetOtp(UUID appId, String challengeId);

  void resetWithOtp(UUID appId, AuthDtos.OtpPasswordResetRequest request);

  AppUser current(UUID appId, UUID id);

  com.authplatform.auth.dto.MfaDtos.Status mfaStatus(UUID appId, UUID id);
}
