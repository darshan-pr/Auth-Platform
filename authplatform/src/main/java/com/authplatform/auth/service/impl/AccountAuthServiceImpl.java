package com.authplatform.auth.service.impl;

import com.authplatform.audit.AuditService;
import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.auth.entity.EmailToken;
import com.authplatform.auth.entity.EmailTokenType;
import com.authplatform.auth.service.AccountAuthService;
import com.authplatform.auth.service.JwtService;
import com.authplatform.auth.service.LoginAttemptService;
import com.authplatform.auth.service.OneTimeTokenService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.user.entity.Account;
import com.authplatform.user.entity.PlatformRole;
import com.authplatform.user.repository.AccountRepository;
import java.time.Duration;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountAuthServiceImpl implements AccountAuthService {
  private final AccountRepository accounts;
  private final PasswordHasher passwords;
  private final OneTimeTokenService tokens;
  private final SessionService sessions;
  private final JwtService jwt;
  private final LoginAttemptService attempts;
  private final EmailSender email;
  private final EmailTemplateService templates;
  private final AuditService audit;
  private final com.authplatform.auth.service.MfaService mfa;
  private final String dummyHash;

  public AccountAuthServiceImpl(
      AccountRepository accounts,
      PasswordHasher passwords,
      OneTimeTokenService tokens,
      SessionService sessions,
      JwtService jwt,
      LoginAttemptService attempts,
      EmailSender email,
      EmailTemplateService templates,
      AuditService audit,
      com.authplatform.auth.service.MfaService mfa) {
    this.accounts = accounts;
    this.passwords = passwords;
    this.tokens = tokens;
    this.sessions = sessions;
    this.jwt = jwt;
    this.attempts = attempts;
    this.email = email;
    this.templates = templates;
    this.audit = audit;
    this.mfa = mfa;
    this.dummyHash = passwords.hash("dummy-password-for-timing-only");
  }

  @Transactional
  public AuthDtos.SignupResponse register(AuthDtos.RegisterRequest request) {
    String normalized = normalize(request.email());
    validatePassword(request.password(), normalized);
    if (accounts.existsByEmailIgnoreCase(normalized)) {
      passwords.matches(request.password(), dummyHash);
      return new AuthDtos.SignupResponse(
          null,
          normalized,
          false,
          "If the account can be registered, a verification email will be sent");
    }
    Account account;
    try {
      account =
          accounts.saveAndFlush(
              Account.register(
                  normalized, passwords.hash(request.password()), request.name().trim()));
    } catch (org.springframework.dao.DataIntegrityViolationException ex) {
      throw new ApiException(ErrorCode.EMAIL_TAKEN);
    }
    String raw = tokens.issueAccount(account.getId(), EmailTokenType.VERIFY_EMAIL).rawToken();
    email.send(
        templates.emailVerification(
            null,
            normalized,
            account.getName(),
            "http://localhost:8080/api/console/auth/verify-email?token=" + raw));
    audit.recordAccount("SIGNUP", account.getId(), null);
    return new AuthDtos.SignupResponse(
        account.getId(),
        account.getEmail(),
        false,
        "If the account can be registered, a verification email will be sent");
  }

  @Transactional
  public AuthDtos.VerifyResponse verify(String raw) {
    EmailToken token = tokens.consume(raw, EmailTokenType.VERIFY_EMAIL);
    Account account =
        accounts
            .findById(token.getAccountId())
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    boolean wasVerified = account.isEmailVerified();
    account.markEmailVerified();
    if (!wasVerified) email.send(templates.welcome(null, account.getEmail(), account.getName()));
    audit.recordAccount("EMAIL_VERIFIED", account.getId(), null);
    return new AuthDtos.VerifyResponse(true);
  }

  public void resend(String emailAddress) {
    accounts
        .findByEmailIgnoreCase(normalize(emailAddress))
        .ifPresent(
            account -> {
              String raw =
                  tokens.issueAccount(account.getId(), EmailTokenType.VERIFY_EMAIL).rawToken();
              email.send(
                  templates.emailVerification(
                      null,
                      account.getEmail(),
                      account.getName(),
                      "http://localhost:8080/api/console/auth/verify-email?token=" + raw));
            });
  }

  @Transactional
  public AuthDtos.ConsoleLoginResult login(AuthDtos.LoginRequest request, String ip, String agent) {
    String emailAddress = normalize(request.email());
    String key = "CONSOLE:" + emailAddress;
    attempts.assertNotLocked(key);
    Account account = accounts.findByEmailIgnoreCase(emailAddress).orElse(null);
    boolean valid =
        account != null
            ? passwords.matches(request.password(), account.getPasswordHash())
            : passwords.matches(request.password(), dummyHash);
    if (!valid) {
      if (attempts.recordFailure(key) && account != null) {
        email.send(
            templates.temporaryLock(
                null, account.getEmail(), account.getName(), attempts.lockDuration()));
      }
      audit.recordAccount("LOGIN_FAILED", account == null ? null : account.getId(), ip);
      throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
    }
    attempts.clearFailures(key);
    if (account.getPlatformRole() == PlatformRole.SA || !account.isEmailVerified())
      throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
    var challenge = mfa.issueConsoleAccountOtp(account);
    return new AuthDtos.ConsoleLoginResult(
        null,
        challenge.expiresIn(),
        null,
        null,
        true,
        challenge.challengeId(),
        challenge.message());
  }

  @Transactional
  public AuthDtos.ConsoleLoginResult verifyOtp(
      String challengeId, String code, String ip, String agent) {
    UUID accountId = mfa.verifyConsoleAccountOtp(challengeId, code);
    Account account =
        accounts
            .findById(accountId)
            .orElseThrow(() -> new ApiException(ErrorCode.INVALID_CREDENTIALS));
    if (account.getPlatformRole() == PlatformRole.SA)
      throw new ApiException(ErrorCode.ACCESS_DENIED, "Use the SA login endpoint");
    if (!"ACTIVE".equals(account.getStatus())) throw new ApiException(ErrorCode.ACCESS_DENIED);
    SessionService.StartedSession started = sessions.startForAccount(account.getId(), ip, agent);
    Duration accessTtl = sessions.accessTokenTtl(started.session());
    String access =
        jwt.issue(
            account.getId(),
            null,
            started.session().getId(),
            account.getPlatformRole().name(),
            null,
            null,
            accessTtl);
    audit.recordAccount("LOGIN_SUCCESS", account.getId(), ip);
    email.send(
        templates.loginDetected(
            null, account.getEmail(), account.getName(), ip, agent, java.time.Instant.now()));
    return new AuthDtos.ConsoleLoginResult(
        access,
        accessTtl.toSeconds(),
        new AuthDtos.AccountSummary(
            account.getId(),
            account.getName(),
            account.getEmail(),
            account.getPlatformRole().name()),
        started.rawRefreshToken());
  }

  public MfaDtos.OtpChallenge resendLoginOtp(String challengeId) {
    return mfa.resendConsoleAccountOtp(challengeId);
  }

  public AuthDtos.ConsoleRefreshResult refresh(String raw) {
    SessionService.RotatedSession rotated = sessions.rotate(raw);
    Account account =
        accounts
            .findById(rotated.session().getAccountId())
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    Duration accessTtl = sessions.accessTokenTtl(rotated.session());
    return new AuthDtos.ConsoleRefreshResult(
        jwt.issue(
            account.getId(),
            null,
            rotated.session().getId(),
            account.getPlatformRole().name(),
            null,
            null,
            accessTtl),
        accessTtl.toSeconds(),
        rotated.rawRefreshToken());
  }

  public void logout(String raw) {
    sessions.revoke(raw);
  }

  public MfaDtos.OtpChallenge forgot(String emailAddress) {
    String normalizedEmail = normalize(emailAddress);
    Account account =
        accounts
            .findByEmailIgnoreCase(normalizedEmail)
            .filter(value -> value.getPlatformRole() != PlatformRole.SA)
            .orElse(null);
    if (account != null) {
      audit.recordAccount("PASSWORD_RESET_REQUESTED", account.getId(), null);
    }
    return mfa.issueConsolePasswordResetOtp(account, normalizedEmail);
  }

  public MfaDtos.OtpChallenge resendPasswordResetOtp(String challengeId) {
    return mfa.resendConsolePasswordResetOtp(challengeId);
  }

  @Transactional
  public void reset(AuthDtos.OtpPasswordResetRequest request) {
    UUID accountId = mfa.verifyConsolePasswordResetOtp(request.challengeId(), request.code());
    Account account =
        accounts.findById(accountId).orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    if (account.getPlatformRole() == PlatformRole.SA) {
      throw new ApiException(ErrorCode.TOKEN_INVALID);
    }
    validatePassword(request.newPassword(), account.getEmail());
    account.changePassword(passwords.hash(request.newPassword()));
    sessions.revokeAllForAccount(account.getId());
    audit.recordAccount("PASSWORD_RESET_COMPLETED", account.getId(), null);
    email.send(templates.passwordChanged(null, account.getEmail(), account.getName()));
  }

  @Transactional(readOnly = true)
  public Account current(UUID id) {
    return accounts.findById(id).orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
  }

  @Transactional(readOnly = true)
  public com.authplatform.auth.dto.MfaDtos.Status mfaStatus(UUID id) {
    return mfa.accountStatus(current(id));
  }

  private static String normalize(String email) {
    return email.trim().toLowerCase(Locale.ROOT);
  }

  private void validatePassword(String password, String email) {
    String local = email.substring(0, email.indexOf('@'));
    if (password.length() < 10
        || password.length() > 128
        || !password.matches(".*[A-Za-z].*")
        || !password.matches(".*\\d.*")
        || password.toLowerCase(Locale.ROOT).contains(local))
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED,
          "Password must be 10-128 characters with a letter and digit and must not contain the email local part");
  }
}
