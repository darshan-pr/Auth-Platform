package com.authplatform.auth.service.impl;

import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.audit.AuditService;
import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.entity.EmailToken;
import com.authplatform.auth.entity.EmailTokenType;
import com.authplatform.auth.service.AppUserAuthService;
import com.authplatform.auth.service.JwtService;
import com.authplatform.auth.service.LoginAttemptService;
import com.authplatform.auth.service.OneTimeTokenService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.role.service.RoleService;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AppUserRepository;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AppUserAuthServiceImpl implements AppUserAuthService {
  private final AppUserRepository users;
  private final AppRepository apps;
  private final PasswordHasher passwords;
  private final OneTimeTokenService tokens;
  private final SessionService sessions;
  private final JwtService jwt;
  private final LoginAttemptService attempts;
  private final EmailSender email;
  private final EmailTemplateService templates;
  private final RoleService roles;
  private final AuditService audit;
  private final com.authplatform.auth.service.MfaService mfa;
  private final String dummyHash;

  public AppUserAuthServiceImpl(
      AppUserRepository users,
      AppRepository apps,
      PasswordHasher passwords,
      OneTimeTokenService tokens,
      SessionService sessions,
      JwtService jwt,
      LoginAttemptService attempts,
      EmailSender email,
      EmailTemplateService templates,
      RoleService roles,
      AuditService audit,
      com.authplatform.auth.service.MfaService mfa) {
    this.users = users;
    this.apps = apps;
    this.passwords = passwords;
    this.tokens = tokens;
    this.sessions = sessions;
    this.jwt = jwt;
    this.attempts = attempts;
    this.email = email;
    this.templates = templates;
    this.roles = roles;
    this.audit = audit;
    this.mfa = mfa;
    this.dummyHash = passwords.hash("dummy-password-for-timing-only");
  }

  @Transactional
  public AuthDtos.UserSummary register(UUID appId, AuthDtos.RegisterRequest request) {
    App app = activeApp(appId);
    String emailAddress = normalize(request.email());
    validatePassword(request.password(), emailAddress);
    if (users.existsByAppIdAndEmailIgnoreCase(appId, emailAddress)) {
      passwords.matches(request.password(), dummyHash);
      return new AuthDtos.UserSummary(
          null, request.name(), emailAddress, false, List.of(), List.of());
    }
    AppUser user;
    try {
      user =
          users.saveAndFlush(
              AppUser.register(
                  appId, emailAddress, passwords.hash(request.password()), request.name().trim()));
    } catch (org.springframework.dao.DataIntegrityViolationException ex) {
      throw new ApiException(ErrorCode.EMAIL_TAKEN);
    }
    roles.assignDefaultRole(appId, user.getId());
    String raw = tokens.issueAppUser(user.getId(), EmailTokenType.VERIFY_EMAIL).rawToken();
    email.send(templates.emailVerification(app, user.getEmail(), user.getName(), verificationLink(app, raw)));
    audit.recordAppUser("SIGNUP", user.getId(), appId, null);
    return summary(appId, user);
  }

  @Transactional
  public AuthDtos.VerifyResponse verify(UUID appId, String raw) {
    EmailToken token = tokens.consume(raw, EmailTokenType.VERIFY_EMAIL);
    AppUser user =
        users
            .findByAppIdAndId(appId, token.getAppUserId())
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    App app = apps.findById(appId).orElseThrow(() -> new ApiException(ErrorCode.INVALID_KEY));
    boolean wasVerified = user.isEmailVerified();
    user.markEmailVerified();
    if (!wasVerified) email.send(templates.welcome(app, user.getEmail(), user.getName()));
    audit.recordAppUser("EMAIL_VERIFIED", user.getId(), appId, null);
    return new AuthDtos.VerifyResponse(true);
  }

  public void resend(UUID appId, String emailAddress) {
    apps.findById(appId)
        .ifPresent(
            app ->
                users
                    .findByAppIdAndEmailIgnoreCase(appId, normalize(emailAddress))
                    .ifPresent(
                        user -> {
                          String raw =
                              tokens
                                  .issueAppUser(user.getId(), EmailTokenType.VERIFY_EMAIL)
                                  .rawToken();
                          email.send(
                              templates.emailVerification(
                                  app, user.getEmail(), user.getName(), verificationLink(app, raw)));
                        }));
  }

  @Transactional
  public AuthDtos.LoginResponse login(
      UUID appId, AuthDtos.LoginRequest request, String ip, String agent) {
    App app = activeApp(appId);
    String emailAddress = normalize(request.email());
    String key = "APP:" + appId + ":" + emailAddress;
    attempts.assertNotLocked(key);
    AppUser user = users.findByAppIdAndEmailIgnoreCase(appId, emailAddress).orElse(null);
    boolean valid =
        user != null
            ? passwords.matches(request.password(), user.getPasswordHash())
            : passwords.matches(request.password(), dummyHash);
    if (!valid) {
      if (attempts.recordFailure(key) && user != null) {
        email.send(
            templates.temporaryLock(
                app, user.getEmail(), user.getName(), attempts.lockDuration()));
      }
      audit.recordAppUser("LOGIN_FAILED", user == null ? null : user.getId(), appId, ip);
      throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
    }
    attempts.clearFailures(key);
    if (app.isRequireEmailVerification() && !user.isEmailVerified())
      throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
    if (!"ACTIVE".equals(user.getStatus())) throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
    if (app.isMfaRequired()) {
      var challenge = mfa.issueAppUserOtp(app, user);
      return new AuthDtos.LoginResponse(
          null,
          null,
          challenge.expiresIn(),
          null,
          null,
          true,
          challenge.challengeId(),
          challenge.message());
    }
    user.markLogin(Instant.now());
    SessionService.StartedSession started =
        sessions.startForAppUser(
            user.getId(),
            app.getAccessTokenTtlSeconds(),
            app.getRefreshTokenTtlSeconds(),
            ip,
            agent);
    List<String> roleNames = roles.roleNames(appId, user.getId());
    List<String> permissionKeys = roles.permissionKeys(appId, user.getId());
    var accessTtl = sessions.accessTokenTtl(started.session());
    String access =
        jwt.issue(
            user.getId(),
            appId,
            started.session().getId(),
            null,
            roleNames,
            permissionKeys,
            accessTtl);
    audit.recordAppUser("LOGIN_SUCCESS", user.getId(), appId, ip);
    email.send(
        templates.loginDetected(app, user.getEmail(), user.getName(), ip, agent, Instant.now()));
    return new AuthDtos.LoginResponse(
        access,
        started.rawRefreshToken(),
        accessTtl.toSeconds(),
        summary(appId, user),
        null,
        sessions.refreshTokenTtlSeconds(started.session()));
  }

  @Transactional
  public AuthDtos.LoginResponse verifyOtp(
      UUID appId, String challengeId, String code, String ip, String agent) {
    App app = activeApp(appId);
    UUID userId = mfa.verifyAppUserOtp(app, challengeId, code);
    AppUser user =
        users
            .findByAppIdAndId(appId, userId)
            .orElseThrow(() -> new ApiException(ErrorCode.INVALID_CREDENTIALS));
    if (app.isRequireEmailVerification() && !user.isEmailVerified())
      throw new ApiException(ErrorCode.EMAIL_NOT_VERIFIED);
    if (!"ACTIVE".equals(user.getStatus())) throw new ApiException(ErrorCode.USER_BLOCKED);
    user.markLogin(Instant.now());
    SessionService.StartedSession started =
        sessions.startForAppUser(
            user.getId(),
            app.getAccessTokenTtlSeconds(),
            app.getRefreshTokenTtlSeconds(),
            ip,
            agent);
    List<String> roleNames = roles.roleNames(appId, user.getId());
    List<String> permissionKeys = roles.permissionKeys(appId, user.getId());
    var accessTtl = sessions.accessTokenTtl(started.session());
    String access =
        jwt.issue(
            user.getId(),
            appId,
            started.session().getId(),
            null,
            roleNames,
            permissionKeys,
            accessTtl);
    audit.recordAppUser("LOGIN_SUCCESS", user.getId(), appId, ip);
    email.send(
        templates.loginDetected(app, user.getEmail(), user.getName(), ip, agent, Instant.now()));
    return new AuthDtos.LoginResponse(
        access,
        started.rawRefreshToken(),
        accessTtl.toSeconds(),
        summary(appId, user),
        null,
        sessions.refreshTokenTtlSeconds(started.session()));
  }

  public com.authplatform.auth.dto.MfaDtos.OtpChallenge resendLoginOtp(
      UUID appId, String challengeId) {
    App app = activeApp(appId);
    return mfa.resendAppUserOtp(app, challengeId);
  }

  @Transactional
  public AuthDtos.LoginResponse refresh(UUID appId, String raw) {
    App app = activeApp(appId);
    UUID userId = sessions.require(raw).getAppUserId();
    AppUser user =
        users
            .findByAppIdAndId(appId, userId)
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    ensureSessionEligible(app, user);
    SessionService.RotatedSession rotated = sessions.rotate(raw);
    List<String> roleNames = roles.roleNames(appId, user.getId());
    List<String> permissionKeys = roles.permissionKeys(appId, user.getId());
    var accessTtl = sessions.accessTokenTtl(rotated.session());
    return new AuthDtos.LoginResponse(
        jwt.issue(
            user.getId(),
            appId,
            rotated.session().getId(),
            null,
            roleNames,
            permissionKeys,
            accessTtl),
        rotated.rawRefreshToken(),
        accessTtl.toSeconds(),
        summary(appId, user),
        null,
        sessions.refreshTokenTtlSeconds(rotated.session()));
  }

  public void logout(String raw) {
    sessions.revoke(raw);
  }

  public void forgot(UUID appId, String emailAddress) {
    apps.findById(appId)
        .ifPresent(
            app ->
                users
                    .findByAppIdAndEmailIgnoreCase(appId, normalize(emailAddress))
                    .ifPresent(
                        user -> {
                          String raw =
                              tokens
                                  .issueAppUser(user.getId(), EmailTokenType.RESET_PASSWORD)
                                  .rawToken();
                          email.send(
                              templates.passwordReset(
                                  app,
                                  user.getEmail(),
                                  user.getName(),
                                  link(app.getResetPasswordUrl(), raw, "reset-password")));
                          audit.recordAppUser(
                              "PASSWORD_RESET_REQUESTED", user.getId(), appId, null);
                        }));
  }

  @Transactional
  public void reset(UUID appId, AuthDtos.ResetPasswordRequest request) {
    EmailToken token = tokens.consume(request.token(), EmailTokenType.RESET_PASSWORD);
    AppUser user =
        users
            .findByAppIdAndId(appId, token.getAppUserId())
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    App app = apps.findById(appId).orElseThrow(() -> new ApiException(ErrorCode.INVALID_KEY));
    validatePassword(request.newPassword(), user.getEmail());
    user.changePassword(passwords.hash(request.newPassword()));
    sessions.revokeAllForAppUser(user.getId());
    audit.recordAppUser("PASSWORD_RESET_COMPLETED", user.getId(), appId, null);
    email.send(templates.passwordChanged(app, user.getEmail(), user.getName()));
  }

  @Transactional
  public com.authplatform.auth.dto.MfaDtos.OtpChallenge forgotWithOtp(
      UUID appId, String emailAddress) {
    App app = activeApp(appId);
    String normalizedEmail = normalize(emailAddress);
    AppUser user = users.findByAppIdAndEmailIgnoreCase(appId, normalizedEmail).orElse(null);
    if (user != null) {
      audit.recordAppUser("PASSWORD_RESET_REQUESTED", user.getId(), appId, null);
    }
    return mfa.issueAppUserPasswordResetOtp(app, user, normalizedEmail);
  }

  public com.authplatform.auth.dto.MfaDtos.OtpChallenge resendPasswordResetOtp(
      UUID appId, String challengeId) {
    App app = activeApp(appId);
    return mfa.resendAppUserPasswordResetOtp(app, challengeId);
  }

  @Transactional
  public void resetWithOtp(UUID appId, AuthDtos.OtpPasswordResetRequest request) {
    App app = activeApp(appId);
    UUID userId =
        mfa.verifyAppUserPasswordResetOtp(app, request.challengeId(), request.code());
    AppUser user =
        users
            .findByAppIdAndId(appId, userId)
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    validatePassword(request.newPassword(), user.getEmail());
    user.changePassword(passwords.hash(request.newPassword()));
    sessions.revokeAllForAppUser(user.getId());
    audit.recordAppUser("PASSWORD_RESET_COMPLETED", user.getId(), appId, null);
    email.send(templates.passwordChanged(app, user.getEmail(), user.getName()));
  }

  @Transactional(readOnly = true)
  public AppUser current(UUID appId, UUID id) {
    App app = activeApp(appId);
    AppUser user =
        users
        .findByAppIdAndId(appId, id)
        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    ensureSessionEligible(app, user);
    return user;
  }

  private AuthDtos.UserSummary summary(UUID appId, AppUser user) {
    return new AuthDtos.UserSummary(
        user.getId(),
        user.getName(),
        user.getEmail(),
        user.isEmailVerified(),
        roles.roleNames(appId, user.getId()),
        roles.permissionKeys(appId, user.getId()));
  }

  @Transactional(readOnly = true)
  public com.authplatform.auth.dto.MfaDtos.Status mfaStatus(UUID appId, UUID id) {
    App app = activeApp(appId);
    AppUser user = current(appId, id);
    return mfa.appUserStatus(app, user);
  }

  private App activeApp(UUID id) {
    App app = apps.findById(id).orElseThrow(() -> new ApiException(ErrorCode.INVALID_KEY));
    if (!"ACTIVE".equals(app.getStatus())) throw new ApiException(ErrorCode.APP_SUSPENDED);
    return app;
  }

  private static void ensureSessionEligible(App app, AppUser user) {
    if (!"ACTIVE".equals(user.getStatus())) throw new ApiException(ErrorCode.USER_BLOCKED);
    if (app.isRequireEmailVerification() && !user.isEmailVerified())
      throw new ApiException(ErrorCode.EMAIL_NOT_VERIFIED);
  }

  private static String normalize(String email) {
    return email.trim().toLowerCase(Locale.ROOT);
  }

  private String verificationLink(App app, String token) {
    return templates.appVerificationLink(app, token);
  }

  private String link(String configured, String token, String suffix) {
    return configured == null || configured.isBlank()
        ? "http://localhost:3000/" + suffix + "?token=" + token
        : configured + "?token=" + token;
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
