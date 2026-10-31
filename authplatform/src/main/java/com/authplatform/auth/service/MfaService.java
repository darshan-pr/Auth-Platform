package com.authplatform.auth.service;

import com.authplatform.app.entity.App;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.user.entity.Account;
import com.authplatform.user.entity.AppUser;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
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
  private final EmailTemplateService templates;
  private final SecureRandom random = new SecureRandom();

  public MfaService(
      StringRedisTemplate redis, EmailSender email, EmailTemplateService templates) {
    this.redis = redis;
    this.email = email;
    this.templates = templates;
  }

  public MfaDtos.Status accountStatus(Account account) {
    return new MfaDtos.Status(true, true, false);
  }

  public MfaDtos.Status appUserStatus(App app, AppUser user) {
    boolean required = app.isMfaRequired();
    return new MfaDtos.Status(required, required, false);
  }

  public MfaDtos.OtpChallenge issueConsoleAccountOtp(Account account) {
    return issue(
        "CONSOLE_ACCOUNT", account.getId().toString(), account.getEmail(), account.getName(), null);
  }

  public MfaDtos.OtpChallenge issueSaAccountOtp(Account account) {
    return issue("SA_ACCOUNT", account.getId().toString(), account.getEmail(), account.getName(), null);
  }

  public MfaDtos.OtpChallenge issueConsolePasswordResetOtp(Account account, String emailAddress) {
    return issue(
        "CONSOLE_PASSWORD_RESET",
        account == null ? UUID.randomUUID().toString() : account.getId().toString(),
        emailAddress,
        account == null ? null : account.getName(),
        null,
        account != null);
  }

  public MfaDtos.OtpChallenge issueSaPasswordResetOtp(Account account, String emailAddress) {
    return issue(
        "SA_PASSWORD_RESET",
        account == null ? UUID.randomUUID().toString() : account.getId().toString(),
        emailAddress,
        account == null ? null : account.getName(),
        null,
        account != null);
  }

  public MfaDtos.OtpChallenge issueAppUserOtp(App app, AppUser user) {
    return issue(
        "APP_USER:" + app.getId(),
        user.getId().toString(),
        user.getEmail(),
        user.getName(),
        app);
  }

  public MfaDtos.OtpChallenge issueAppUserPasswordResetOtp(
      App app, AppUser user, String emailAddress) {
    return issue(
        "APP_USER_PASSWORD_RESET:" + app.getId(),
        user == null ? UUID.randomUUID().toString() : user.getId().toString(),
        emailAddress,
        user == null ? null : user.getName(),
        app,
        user != null);
  }

  public MfaDtos.OtpChallenge resendAppUserOtp(App app, String challengeId) {
    return resend(challengeId, "APP_USER:" + app.getId(), app);
  }

  public MfaDtos.OtpChallenge resendAppUserPasswordResetOtp(App app, String challengeId) {
    return resend(challengeId, "APP_USER_PASSWORD_RESET:" + app.getId(), app);
  }

  public UUID verifyConsoleAccountOtp(String challengeId, String code) {
    return verify("CONSOLE_ACCOUNT", null, challengeId, code, null);
  }

  public UUID verifySaAccountOtp(String challengeId, String code) {
    return verify("SA_ACCOUNT", null, challengeId, code, null);
  }

  public UUID verifyConsolePasswordResetOtp(String challengeId, String code) {
    return verify("CONSOLE_PASSWORD_RESET", null, challengeId, code, null);
  }

  public UUID verifySaPasswordResetOtp(String challengeId, String code) {
    return verify("SA_PASSWORD_RESET", null, challengeId, code, null);
  }

  public MfaDtos.OtpChallenge resendConsoleAccountOtp(String challengeId) {
    return resend(challengeId, "CONSOLE_ACCOUNT", null);
  }

  public MfaDtos.OtpChallenge resendSaAccountOtp(String challengeId) {
    return resend(challengeId, "SA_ACCOUNT", null);
  }

  public MfaDtos.OtpChallenge resendConsolePasswordResetOtp(String challengeId) {
    return resend(challengeId, "CONSOLE_PASSWORD_RESET", null);
  }

  public MfaDtos.OtpChallenge resendSaPasswordResetOtp(String challengeId) {
    return resend(challengeId, "SA_PASSWORD_RESET", null);
  }

  public UUID verifyAppUserOtp(App app, String challengeId, String code) {
    return verify("APP_USER:" + app.getId(), null, challengeId, code, app);
  }

  public UUID verifyAppUserPasswordResetOtp(App app, String challengeId, String code) {
    return verify("APP_USER_PASSWORD_RESET:" + app.getId(), null, challengeId, code, app);
  }

  private MfaDtos.OtpChallenge issue(
      String type, String subjectId, String address, String name, App app) {
    return issue(type, subjectId, address, name, app, true);
  }

  private MfaDtos.OtpChallenge issue(
      String type, String subjectId, String address, String name, App app, boolean deliver) {
    String challengeId = randomToken();
    String code = String.format("%06d", random.nextInt(1_000_000));
    ChallengeData challenge =
        new ChallengeData(
            type,
            subjectId,
            deliver ? address : "",
            deliver && name != null ? name : "",
            code);
    put(otpKey(challengeId), serialize(challenge));
    if (deliver) sendCode(address, type, code, app, name);
    return new MfaDtos.OtpChallenge(
        challengeId,
        OTP_TTL.toSeconds(),
        "If the account exists, a one-time password was sent to its email address.");
  }

  private MfaDtos.OtpChallenge resend(String challengeId, String expectedType, App app) {
    if (challengeId == null || challengeId.isBlank()) throw new ApiException(ErrorCode.MFA_INVALID);
    String key = otpKey(challengeId);
    String value = get(key);
    if (value == null) throw new ApiException(ErrorCode.OTP_EXPIRED);
    ChallengeData challenge = parse(value);
    if (!expectedType.equals(challenge.type())) {
      throw new ApiException(ErrorCode.MFA_INVALID);
    }
    enforceResendLimit(challengeId);
    String code = String.format("%06d", random.nextInt(1_000_000));
    put(key, serialize(challenge.withCode(code)));
    if (!challenge.address().isBlank()) {
      sendCode(challenge.address(), expectedType, code, app, challenge.name());
    }
    return new MfaDtos.OtpChallenge(
        challengeId,
        OTP_TTL.toSeconds(),
        "If the account exists, a one-time password was sent to its email address.");
  }

  private void sendCode(String address, String type, String code, App app, String name) {
    boolean passwordReset = type.endsWith("PASSWORD_RESET");
    email.send(templates.oneTimeCode(app, address, name, code, passwordReset));
  }

  private UUID verify(
      String expectedType, String expectedSubject, String challengeId, String code, App app) {
    if (challengeId == null || challengeId.isBlank() || code == null || !code.matches("\\d{6}")) {
      throw new ApiException(ErrorCode.MFA_INVALID);
    }
    String key = otpKey(challengeId);
    String value = get(key);
    if (value == null) throw new ApiException(ErrorCode.OTP_EXPIRED);
    ChallengeData challenge = parse(value);
    if (!expectedType.equals(challenge.type())
        || (expectedSubject != null && !expectedSubject.equals(challenge.subjectId()))) {
      throw new ApiException(ErrorCode.MFA_INVALID);
    }
    enforceAttempts(challengeId, challenge, app);
    if (!challenge.code().equals(code)) throw new ApiException(ErrorCode.MFA_INVALID);
    delete(key);
    delete(attemptKey(challengeId));
    return UUID.fromString(challenge.subjectId());
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

  private void enforceAttempts(String challengeId, ChallengeData challenge, App app) {
    try {
      Long attempts = redis.opsForValue().increment(attemptKey(challengeId));
      redis.expire(attemptKey(challengeId), ATTEMPT_TTL);
      if (attempts != null && attempts > 10) {
        if (attempts == 11 && !challenge.address().isBlank()) {
          email.send(
              templates.temporaryLock(
                  app, challenge.address(), challenge.name(), ATTEMPT_TTL));
        }
        throw new ApiException(ErrorCode.ACCOUNT_LOCKED);
      }
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

  private static String serialize(ChallengeData challenge) {
    String encodedName =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(challenge.name().getBytes(StandardCharsets.UTF_8));
    return challenge.type()
        + "|"
        + challenge.subjectId()
        + "|"
        + challenge.address()
        + "|"
        + encodedName
        + "|"
        + challenge.code();
  }

  private static ChallengeData parse(String value) {
    String[] parts = value.split("\\|", 5);
    if (parts.length == 5) {
      try {
        String name =
            new String(Base64.getUrlDecoder().decode(parts[3]), StandardCharsets.UTF_8);
        return new ChallengeData(parts[0], parts[1], parts[2], name, parts[4]);
      } catch (IllegalArgumentException ex) {
        throw new ApiException(ErrorCode.MFA_INVALID);
      }
    }
    if (parts.length == 4) return new ChallengeData(parts[0], parts[1], parts[2], "", parts[3]);
    if (parts.length == 3) return new ChallengeData(parts[0], parts[1], "", "", parts[2]);
    throw new ApiException(ErrorCode.MFA_INVALID);
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

  private record ChallengeData(
      String type, String subjectId, String address, String name, String code) {
    private ChallengeData withCode(String nextCode) {
      return new ChallengeData(type, subjectId, address, name, nextCode);
    }
  }
}
