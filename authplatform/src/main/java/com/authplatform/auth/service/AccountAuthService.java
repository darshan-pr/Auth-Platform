package com.authplatform.auth.service;

import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.user.entity.Account;
import java.util.UUID;

public interface AccountAuthService {
  AuthDtos.SignupResponse register(AuthDtos.RegisterRequest request);

  AuthDtos.VerifyResponse verify(String token);

  void resend(String email);

  AuthDtos.ConsoleLoginResult login(AuthDtos.LoginRequest request, String ip, String agent);

  AuthDtos.ConsoleLoginResult verifyOtp(String challengeId, String code, String ip, String agent);

  MfaDtos.OtpChallenge resendLoginOtp(String challengeId);

  AuthDtos.ConsoleRefreshResult refresh(String refreshToken);

  void logout(String refreshToken);

  MfaDtos.OtpChallenge forgot(String email);

  MfaDtos.OtpChallenge resendPasswordResetOtp(String challengeId);

  void reset(AuthDtos.OtpPasswordResetRequest request);

  Account current(UUID id);

  com.authplatform.auth.dto.MfaDtos.Status mfaStatus(UUID id);
}
