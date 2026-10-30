package com.authplatform.auth.service;

import com.authplatform.app.entity.App;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailSender;
import com.authplatform.user.entity.Account;
import com.authplatform.user.entity.AppUser;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/** Email one-time passwords used as the first MFA method. */
@Service
public class MfaService {
  private static final Duration OTP_TTL = Duration.ofMinutes(5);
  private static final Duration ATTEMPT_TTL = Duration.ofMinutes(5);
  private static final int MAX_RESENDS = 3;
  private final StringRedisTemplate redis;
  private final EmailSender email;
  private final SecureRandom random = new SecureRandom();

  public MfaService(StringRedisTemplate redis, EmailSender email) {
    this.redis = redis;
    this.email = email;
  }

  public MfaDtos.Status accountStatus(Account account) {
    return new MfaDtos.Status(true, true, false);
  }

  public MfaDtos.Status appUserStatus(App app, AppUser user) {
    boolean required = app.isMfaRequired();
    return new MfaDtos.Status(required, required, false);
  }

  public MfaDtos.OtpChallenge issueConsoleAccountOtp(Account account) {
    return issue("CONSOLE_ACCOUNT", account.getId().toString(), account.getEmail());
  }

  public MfaDtos.OtpChallenge issueSaAccountOtp(Account account) {
    return issue("SA_ACCOUNT", account.getId().toString(), account.getEmail());
  }

  public MfaDtos.OtpChallenge issueConsolePasswordResetOtp(Account account, String emailAddress) {
    return issue(
        "CONSOLE_PASSWORD_RESET",
        account == null ? UUID.randomUUID().toString() : account.getId().toString(),
        emailAddress,
        account != null);
  }

  public MfaDtos.OtpChallenge issueSaPasswordResetOtp(Account account, String emailAddress) {
    return issue(
        "SA_PASSWORD_RESET",
        account == null ? UUID.randomUUID().toString() : account.getId().toString(),
        emailAddress,
        account != null);
  }

  public MfaDtos.OtpChallenge issueAppUserOtp(App app, AppUser user) {
    return issue("APP_USER:" + app.getId(), user.getId().toString(), user.getEmail());
  }

  public MfaDtos.OtpChallenge issueAppUserPasswordResetOtp(
      UUID appId, AppUser user, String emailAddress) {
    return issue(
        "APP_USER_PASSWORD_RESET:" + appId,
        user == null ? UUID.randomUUID().toString() : user.getId().toString(),
        emailAddress,
        user != null);
  }

  public MfaDtos.OtpChallenge resendAppUserOtp(UUID appId, String challengeId) {
    return resend(challengeId, "APP_USER:" + appId);
  }

  public MfaDtos.OtpChallenge resendAppUserPasswordResetOtp(UUID appId, String challengeId) {
    return resend(challengeId, "APP_USER_PASSWORD_RESET:" + appId);
  }

  public UUID verifyConsoleAccountOtp(String challengeId, String code) {
    return verify("CONSOLE_ACCOUNT", null, challengeId, code);
  }

  public UUID verifySaAccountOtp(String challengeId, String code) {
    return verify("SA_ACCOUNT", null, challengeId, code);
  }

  public UUID verifyConsolePasswordResetOtp(String challengeId, String code) {
    return verify("CONSOLE_PASSWORD_RESET", null, challengeId, code);
  }

  public UUID verifySaPasswordResetOtp(String challengeId, String code) {
    return verify("SA_PASSWORD_RESET", null, challengeId, code);
  }

  public MfaDtos.OtpChallenge resendConsoleAccountOtp(String challengeId) {
    return resend(challengeId, "CONSOLE_ACCOUNT");
  }

  public MfaDtos.OtpChallenge resendSaAccountOtp(String challengeId) {
    return resend(challengeId, "SA_ACCOUNT");
  }

  public MfaDtos.OtpChallenge resendConsolePasswordResetOtp(String challengeId) {
    return resend(challengeId, "CONSOLE_PASSWORD_RESET");
  }

  public MfaDtos.OtpChallenge resendSaPasswordResetOtp(String challengeId) {
    return resend(challengeId, "SA_PASSWORD_RESET");
  }

  public UUID verifyAppUserOtp(UUID appId, String challengeId, String code) {
    return verify("APP_USER:" + appId, null, challengeId, code);
  }

  public UUID verifyAppUserPasswordResetOtp(UUID appId, String challengeId, String code) {
    return verify("APP_USER_PASSWORD_RESET:" + appId, null, challengeId, code);
  }

  private MfaDtos.OtpChallenge issue(String type, String subjectId, String address) {
    return issue(type, subjectId, address, true);
  }

  private MfaDtos.OtpChallenge issue(
      String type, String subjectId, String address, boolean deliver) {
    String challengeId = randomToken();
    String code = String.format("%06d", random.nextInt(1_000_000));
    put(otpKey(challengeId), type + "|" + subjectId + "|" + (deliver ? address : "") + "|" + code);
    if (deliver) sendCode(address, type, code);
    return new MfaDtos.OtpChallenge(
        challengeId,
        OTP_TTL.toSeconds(),
        "If the account exists, a one-time password was sent to its email address.");
  }

  private MfaDtos.OtpChallenge resend(String challengeId, String expectedType) {
    if (challengeId == null || challengeId.isBlank()) throw new ApiException(ErrorCode.MFA_INVALID);
    String key = otpKey(challengeId);
    String value = get(key);
    if (value == null) throw new ApiException(ErrorCode.OTP_EXPIRED);
    String[] parts = value.split("\\|", 4);
    if (parts.length != 4 || !expectedType.equals(parts[0])) {
      throw new ApiException(ErrorCode.MFA_INVALID);
    }
    enforceResendLimit(challengeId);
    String code = String.format("%06d", random.nextInt(1_000_000));
    put(key, parts[0] + "|" + parts[1] + "|" + parts[2] + "|" + code);
    if (!parts[2].isBlank()) sendCode(parts[2], expectedType, code);
    return new MfaDtos.OtpChallenge(
        challengeId,
        OTP_TTL.toSeconds(),
        "If the account exists, a one-time password was sent to its email address.");
  }

  private void sendCode(String address, String type, String code) {
    boolean passwordReset = type.endsWith("PASSWORD_RESET");
    email.sendText(
        address,
        passwordReset
            ? "Your Auth Platform password reset code"
            : "Your Auth Platform sign-in code",
        "Your one-time password is "
            + code
            + ". It expires in 5 minutes. If you did not request this, you can ignore this email.");
  }

  private UUID verify(
      String expectedType, String expectedSubject, String challengeId, String code) {
    if (challengeId == null || challengeId.isBlank() || code == null || !code.matches("\\d{6}")) {
      throw new ApiException(ErrorCode.MFA_INVALID);
    }
    String key = otpKey(challengeId);
    String value = get(key);
    if (value == null) throw new ApiException(ErrorCode.OTP_EXPIRED);
    String[] parts = value.split("\\|", 4);
    if ((parts.length != 3 && parts.length != 4)
        || !expectedType.equals(parts[0])
        || (expectedSubject != null && !expectedSubject.equals(parts[1]))) {
      throw new ApiException(ErrorCode.MFA_INVALID);
    }
    enforceAttempts(challengeId);
    if (!parts[parts.length - 1].equals(code)) throw new ApiException(ErrorCode.MFA_INVALID);
    delete(key);
    delete(attemptKey(challengeId));
    return UUID.fromString(parts[1]);
  }

  private void enforceResendLimit(String challengeId) {
    try {
      Long resends = redis.opsForValue().increment(resendKey(challengeId));
      redis.expire(resendKey(challengeId), OTP_TTL);
      if (resends != null && resends > MAX_RESENDS) {
        throw new ApiException(ErrorCode.RATE_LIMITED);
      }
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }

  private void enforceAttempts(String challengeId) {
    try {
      Long attempts = redis.opsForValue().increment(attemptKey(challengeId));
      redis.expire(attemptKey(challengeId), ATTEMPT_TTL);
      if (attempts != null && attempts > 10) throw new ApiException(ErrorCode.ACCOUNT_LOCKED);
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }

  private void put(String key, String value) {
    try {
      redis.opsForValue().set(key, value, OTP_TTL);
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }

  private String get(String key) {
    try {
      return redis.opsForValue().get(key);
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }

  private void delete(String key) {
    try {
      redis.delete(key);
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }

  private String randomToken() {
    byte[] bytes = new byte[24];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private String otpKey(String challengeId) {
    return "authplatform:mfa:otp:" + challengeId;
  }

  private String attemptKey(String challengeId) {
    return "authplatform:mfa:attempts:" + challengeId;
  }

  private String resendKey(String challengeId) {
    return "authplatform:mfa:resends:" + challengeId;
  }
}
