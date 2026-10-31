package com.authplatform.sa.service;

import com.authplatform.audit.AuditService;
import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.auth.service.JwtService;
import com.authplatform.auth.service.LoginAttemptService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.sa.dto.SaDtos;
import com.authplatform.user.entity.Account;
import com.authplatform.user.entity.PlatformRole;
import com.authplatform.user.repository.AccountRepository;
import java.time.Duration;
import java.util.Locale;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SaAuthService {
  public static final String AUDIENCE = "authplatform-sa";

  private final AccountRepository accounts;
  private final PasswordHasher passwords;
  private final SessionService sessions;
  private final JwtService jwt;
  private final LoginAttemptService attempts;
  private final AuditService audit;
  private final EmailSender email;
  private final EmailTemplateService templates;
  private final com.authplatform.auth.service.MfaService mfa;
  private final String dummyHash;

  public SaAuthService(
      AccountRepository accounts,
      PasswordHasher passwords,
      SessionService sessions,
      JwtService jwt,
      LoginAttemptService attempts,
      AuditService audit,
      EmailSender email,
      EmailTemplateService templates,
      com.authplatform.auth.service.MfaService mfa) {
    this.accounts = accounts;
    this.passwords = passwords;
    this.sessions = sessions;
    this.jwt = jwt;
    this.attempts = attempts;
    this.audit = audit;
    this.email = email;
    this.templates = templates;
    this.mfa = mfa;
    this.dummyHash = passwords.hash("dummy-sa-password-for-timing-only");
  }

  @Transactional
  public SaDtos.LoginResponse login(SaDtos.LoginRequest request, String ip, String agent) {
    String emailAddress = normalize(request.email());
    String key = "SA:" + emailAddress;
    attempts.assertNotLocked(key);
    Account account = accounts.findByEmailIgnoreCase(emailAddress).orElse(null);
    boolean valid =
        account != null
            ? passwords.matches(request.password(), account.getPasswordHash())
            : passwords.matches(request.password(), dummyHash);
    if (!valid || account == null || account.getPlatformRole() != PlatformRole.SA) {
      if (attempts.recordFailure(key) && account != null) {
        email.send(
            templates.temporaryLock(
                null, account.getEmail(), account.getName(), attempts.lockDuration()));
      }
      audit.recordAccount("SA_LOGIN_FAILED", account == null ? null : account.getId(), ip);
      throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
    }
    attempts.clearFailures(key);
    if (!"ACTIVE".equals(account.getStatus())) throw new ApiException(ErrorCode.ACCESS_DENIED);
    if (!account.isEmailVerified()) throw new ApiException(ErrorCode.EMAIL_NOT_VERIFIED);
    var challenge = mfa.issueSaAccountOtp(account);
    return new SaDtos.LoginResponse(
        null,
        challenge.expiresIn(),
        null,
        null,
        true,
        challenge.challengeId(),
        challenge.message());
  }

  @Transactional
  public SaDtos.LoginResponse verifyOtp(String challengeId, String code, String ip, String agent) {
    java.util.UUID accountId = mfa.verifySaAccountOtp(challengeId, code);
    Account account =
        accounts
            .findById(accountId)
            .filter(value -> value.getPlatformRole() == PlatformRole.SA)
            .orElseThrow(
                () -> new ApiException(com.authplatform.common.exception.ErrorCode.ACCESS_DENIED));
    if (!"ACTIVE".equals(account.getStatus())) throw new ApiException(ErrorCode.ACCESS_DENIED);
    SessionService.StartedSession started = sessions.startForAccount(account.getId(), ip, agent);
    Duration accessTtl = sessions.accessTokenTtl(started.session());
    String access =
        jwt.issueForAudience(
            account.getId(),
            started.session().getId(),
            PlatformRole.SA.name(),
            AUDIENCE,
            accessTtl);
    audit.recordSa("SA_LOGIN_SUCCESS", account.getId(), null, ip, null);
    email.send(
        templates.loginDetected(
            null, account.getEmail(), account.getName(), ip, agent, java.time.Instant.now()));
    return new SaDtos.LoginResponse(
        access,
        accessTtl.toSeconds(),
        new SaDtos.AccountView(
            account.getId(),
            account.getName(),
            account.getEmail(),
            account.isEmailVerified(),
            account.getPlatformRole(),
            account.getStatus(),
            account.getCreatedAt(),
            0),
        started.rawRefreshToken());
  }

  public MfaDtos.OtpChallenge resendLoginOtp(String challengeId) {
    return mfa.resendSaAccountOtp(challengeId);
  }

  @Transactional
  public MfaDtos.OtpChallenge forgot(String emailAddress) {
    String email = normalize(emailAddress);
    Account account =
        accounts
            .findByEmailIgnoreCase(email)
            .filter(value -> value.getPlatformRole() == PlatformRole.SA)
            .orElse(null);
    if (account != null) {
      audit.recordSa("SA_PASSWORD_RESET_REQUESTED", account.getId(), null, null, null);
    }
    return mfa.issueSaPasswordResetOtp(account, email);
  }

  public MfaDtos.OtpChallenge resendPasswordResetOtp(String challengeId) {
    return mfa.resendSaPasswordResetOtp(challengeId);
  }

  @Transactional
  public void reset(AuthDtos.OtpPasswordResetRequest request) {
    java.util.UUID accountId = mfa.verifySaPasswordResetOtp(request.challengeId(), request.code());
    Account account =
        accounts
            .findById(accountId)
            .filter(value -> value.getPlatformRole() == PlatformRole.SA)
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    String local = account.getEmail().substring(0, account.getEmail().indexOf('@'));
    String password = request.newPassword();
    if (password.length() < 10
        || password.length() > 128
        || !password.matches(".*[A-Za-z].*")
        || !password.matches(".*\\d.*")
        || password.toLowerCase(Locale.ROOT).contains(local)) {
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED,
          "Password must be 10-128 characters with a letter and digit and must not contain the email local part");
    }
    account.changePassword(passwords.hash(password));
    sessions.revokeAllForAccount(account.getId());
    audit.recordSa("SA_PASSWORD_RESET_COMPLETED", account.getId(), null, null, null);
  }

  @Transactional
  public SaDtos.LoginResponse refresh(String rawRefreshToken) {
    SessionService.RotatedSession rotated = sessions.rotate(rawRefreshToken);
    Account account =
        accounts
            .findById(rotated.session().getAccountId())
            .filter(value -> value.getPlatformRole() == PlatformRole.SA)
            .filter(value -> "ACTIVE".equals(value.getStatus()))
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    Duration accessTtl = sessions.accessTokenTtl(rotated.session());
    String access =
        jwt.issueForAudience(
            account.getId(),
            rotated.session().getId(),
            PlatformRole.SA.name(),
            AUDIENCE,
            accessTtl);
    audit.recordSa("SA_TOKEN_REFRESHED", account.getId(), null, null, null);
    return new SaDtos.LoginResponse(
        access,
        accessTtl.toSeconds(),
        new SaDtos.AccountView(
            account.getId(),
            account.getName(),
            account.getEmail(),
            account.isEmailVerified(),
            account.getPlatformRole(),
            account.getStatus(),
            account.getCreatedAt(),
            0),
        rotated.rawRefreshToken());
  }

  public void logout(String rawRefreshToken) {
    sessions.revoke(rawRefreshToken);
  }

  @Transactional(readOnly = true)
  public com.authplatform.auth.dto.MfaDtos.Status mfaStatus(java.util.UUID id) {
    Account account =
        accounts.findById(id).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    return mfa.accountStatus(account);
  }

  private static String normalize(String email) {
    return email.trim().toLowerCase(Locale.ROOT);
  }
}
