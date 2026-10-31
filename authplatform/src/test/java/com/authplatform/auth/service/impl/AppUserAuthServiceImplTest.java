package com.authplatform.auth.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.audit.AuditService;
import com.authplatform.auth.dto.AuthDtos;
import com.authplatform.auth.dto.MfaDtos;
import com.authplatform.auth.entity.Session;
import com.authplatform.auth.entity.EmailToken;
import com.authplatform.auth.entity.EmailTokenType;
import com.authplatform.auth.service.JwtService;
import com.authplatform.auth.service.LoginAttemptService;
import com.authplatform.auth.service.MfaService;
import com.authplatform.auth.service.OneTimeTokenService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailMessage;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.role.service.RoleService;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AppUserRepository;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AppUserAuthServiceImplTest {
  private final UUID appId = UUID.randomUUID();
  private final UUID userId = UUID.randomUUID();
  private final AppRepository apps = mock(AppRepository.class);
  private final AppUserRepository users = mock(AppUserRepository.class);
  private final PasswordHasher passwords = mock(PasswordHasher.class);
  private final SessionService sessions = mock(SessionService.class);
  private final JwtService jwt = mock(JwtService.class);
  private final LoginAttemptService attempts = mock(LoginAttemptService.class);
  private final OneTimeTokenService tokens = mock(OneTimeTokenService.class);
  private final EmailSender email = mock(EmailSender.class);
  private final RoleService roles = mock(RoleService.class);
  private final AuditService audit = mock(AuditService.class);
  private final MfaService mfa = mock(MfaService.class);
  private final App app = mock(App.class);
  private final AppUser user = mock(AppUser.class);
  private AppUserAuthServiceImpl service;

  @BeforeEach
  void setUp() {
    service =
        new AppUserAuthServiceImpl(
            users,
            apps,
            passwords,
            tokens,
            sessions,
            jwt,
            attempts,
            email,
            new EmailTemplateService(""),
            roles,
            audit,
            mfa);
    when(apps.findById(appId)).thenReturn(Optional.of(app));
    when(app.getStatus()).thenReturn("ACTIVE");
    when(app.getName()).thenReturn("Test App");
    when(app.isMfaRequired()).thenReturn(true);
    when(app.isRequireEmailVerification()).thenReturn(false);
    when(app.getAccessTokenTtlSeconds()).thenReturn(null);
    when(app.getRefreshTokenTtlSeconds()).thenReturn(null);
    when(users.findByAppIdAndEmailIgnoreCase(appId, "user@example.com"))
        .thenReturn(Optional.of(user));
    when(user.getId()).thenReturn(userId);
    when(user.getEmail()).thenReturn("user@example.com");
    when(user.getPasswordHash()).thenReturn("password-hash");
    when(user.getStatus()).thenReturn("ACTIVE");
    when(passwords.matches("Password123!", "password-hash")).thenReturn(true);
  }

  @Test
  void loginRequestsAnOtpOnlyWhenTheAppRequiresMfa() {
    var challenge = new MfaDtos.OtpChallenge("otp-challenge", 300, "Check your email.");
    when(mfa.issueAppUserOtp(app, user)).thenReturn(challenge);

    AuthDtos.LoginResponse result =
        service.login(
            appId,
            new AuthDtos.LoginRequest("user@example.com", "Password123!"),
            "127.0.0.1",
            "test-agent");

    assertThat(result.otpRequired()).isTrue();
    assertThat(result.user()).isNull();
    assertThat(result.account()).isNull();
    assertThat(result.challengeId()).isEqualTo("otp-challenge");
    verify(roles, never()).roleNames(appId, userId);
    verify(roles, never()).permissionKeys(appId, userId);

    when(app.isMfaRequired()).thenReturn(false);
    Session session = mock(Session.class);
    when(sessions.startForAppUser(userId, null, null, "127.0.0.1", "test-agent"))
        .thenReturn(
            new SessionService.StartedSession(
                session, "refresh"));
    when(sessions.accessTokenTtl(session)).thenReturn(Duration.ofMinutes(15));
    when(sessions.refreshTokenTtlSeconds(session)).thenReturn(2_592_000L);
    when(jwt.issue(any(), any(), any(), any(), any(), any(), any())).thenReturn("access");
    when(roles.roleNames(appId, userId)).thenReturn(List.of("member"));
    when(roles.permissionKeys(appId, userId)).thenReturn(List.of("profile:read"));

    AuthDtos.LoginResponse withoutMfa =
        service.login(
            appId,
            new AuthDtos.LoginRequest("user@example.com", "Password123!"),
            "127.0.0.1",
            "test-agent");

    assertThat(withoutMfa.otpRequired()).isFalse();
    assertThat(withoutMfa.accessToken()).isEqualTo("access");
    assertThat(withoutMfa.expiresIn()).isEqualTo(900);
    assertThat(withoutMfa.refreshExpiresIn()).isEqualTo(2_592_000);
    verify(mfa, times(1)).issueAppUserOtp(app, user);
    verify(user).markLogin(any());
    verify(audit).recordAppUser("LOGIN_SUCCESS", userId, appId, "127.0.0.1");
  }

  @Test
  void loginUsesTheAppsCustomAccessAndRefreshLifetimes() {
    when(app.isMfaRequired()).thenReturn(false);
    when(app.getAccessTokenTtlSeconds()).thenReturn(300);
    when(app.getRefreshTokenTtlSeconds()).thenReturn(86_400);
    Session session = mock(Session.class);
    when(sessions.startForAppUser(userId, 300, 86_400, "127.0.0.1", "test-agent"))
        .thenReturn(new SessionService.StartedSession(session, "refresh"));
    when(sessions.accessTokenTtl(session)).thenReturn(Duration.ofMinutes(5));
    when(sessions.refreshTokenTtlSeconds(session)).thenReturn(86_400L);
    when(jwt.issue(any(), any(), any(), any(), any(), any(), any())).thenReturn("custom-access");
    when(roles.roleNames(appId, userId)).thenReturn(List.of("member"));
    when(roles.permissionKeys(appId, userId)).thenReturn(List.of("profile:read"));

    AuthDtos.LoginResponse result =
        service.login(
            appId,
            new AuthDtos.LoginRequest("user@example.com", "Password123!"),
            "127.0.0.1",
            "test-agent");

    assertThat(result.accessToken()).isEqualTo("custom-access");
    assertThat(result.expiresIn()).isEqualTo(300);
    assertThat(result.refreshExpiresIn()).isEqualTo(86_400);
    verify(jwt)
        .issue(
            any(),
            any(),
            any(),
            any(),
            any(),
            any(),
            org.mockito.ArgumentMatchers.eq(Duration.ofMinutes(5)));
  }

  @Test
  void refreshRejectsBlockedUsersBeforeRotatingTheirToken() {
    Session session = mock(Session.class);
    when(sessions.require("refresh")).thenReturn(session);
    when(session.getAppUserId()).thenReturn(userId);
    when(users.findByAppIdAndId(appId, userId)).thenReturn(Optional.of(user));
    when(user.getStatus()).thenReturn("BLOCKED");

    ApiException error =
        assertThrows(ApiException.class, () -> service.refresh(appId, "refresh"));

    assertThat(error.code()).isEqualTo(ErrorCode.USER_BLOCKED);
    verify(sessions, never()).rotate("refresh");
  }

  @Test
  void refreshEnforcesTheAppsEmailVerificationPolicy() {
    Session session = mock(Session.class);
    when(sessions.require("refresh")).thenReturn(session);
    when(session.getAppUserId()).thenReturn(userId);
    when(users.findByAppIdAndId(appId, userId)).thenReturn(Optional.of(user));
    when(app.isRequireEmailVerification()).thenReturn(true);
    when(user.isEmailVerified()).thenReturn(false);

    ApiException error =
        assertThrows(ApiException.class, () -> service.refresh(appId, "refresh"));

    assertThat(error.code()).isEqualTo(ErrorCode.EMAIL_NOT_VERIFIED);
    verify(sessions, never()).rotate("refresh");
  }

  @Test
  void currentRejectsBlockedUsers() {
    when(users.findByAppIdAndId(appId, userId)).thenReturn(Optional.of(user));
    when(user.getStatus()).thenReturn("SUSPENDED");

    ApiException error = assertThrows(ApiException.class, () -> service.current(appId, userId));

    assertThat(error.code()).isEqualTo(ErrorCode.USER_BLOCKED);
  }

  @Test
  void currentEnforcesTheAppsEmailVerificationPolicy() {
    when(users.findByAppIdAndId(appId, userId)).thenReturn(Optional.of(user));
    when(app.isRequireEmailVerification()).thenReturn(true);
    when(user.getStatus()).thenReturn("ACTIVE");
    when(user.isEmailVerified()).thenReturn(false);

    ApiException error = assertThrows(ApiException.class, () -> service.current(appId, userId));

    assertThat(error.code()).isEqualTo(ErrorCode.EMAIL_NOT_VERIFIED);
  }

  @Test
  void refreshRotatesTheTokenForAnEligibleUser() {
    Session session = mock(Session.class);
    when(sessions.require("old-refresh")).thenReturn(session);
    when(session.getAppUserId()).thenReturn(userId);
    when(users.findByAppIdAndId(appId, userId)).thenReturn(Optional.of(user));
    when(sessions.rotate("old-refresh"))
        .thenReturn(new SessionService.RotatedSession(session, "new-refresh"));
    when(sessions.accessTokenTtl(session)).thenReturn(Duration.ofMinutes(15));
    when(sessions.refreshTokenTtlSeconds(session)).thenReturn(300L);

    AuthDtos.LoginResponse result = service.refresh(appId, "old-refresh");

    assertThat(result.refreshToken()).isEqualTo("new-refresh");
    assertThat(result.expiresIn()).isEqualTo(900);
    verify(sessions).require("old-refresh");
    verify(sessions).rotate("old-refresh");
  }

  @Test
  void signupUsesTheApplicationOriginForItsVerificationCallback() {
    AppUser registeredUser = mock(AppUser.class);
    when(app.getVerifyEmailUrl()).thenReturn(null);
    when(app.getAllowedOrigins()).thenReturn(List.of("http://localhost:3001"));
    when(users.existsByAppIdAndEmailIgnoreCase(appId, "new@example.com")).thenReturn(false);
    when(users.saveAndFlush(any(AppUser.class))).thenReturn(registeredUser);
    when(registeredUser.getId()).thenReturn(userId);
    when(registeredUser.getEmail()).thenReturn("new@example.com");
    when(registeredUser.getName()).thenReturn("New User");
    when(passwords.hash("SafePass123!")).thenReturn("password-hash");
    when(tokens.issueAppUser(userId, EmailTokenType.VERIFY_EMAIL))
        .thenReturn(new OneTimeTokenService.Issued("verify-token", mock(EmailToken.class)));
    when(roles.roleNames(appId, userId)).thenReturn(List.of());
    when(roles.permissionKeys(appId, userId)).thenReturn(List.of());

    service.register(
        appId, new AuthDtos.RegisterRequest("New User", "new@example.com", "SafePass123!"));

    ArgumentCaptor<EmailMessage> message = ArgumentCaptor.forClass(EmailMessage.class);
    verify(email).send(message.capture());
    assertThat(message.getValue().to()).isEqualTo("new@example.com");
    assertThat(message.getValue().fromName()).isEqualTo("Test App");
    assertThat(message.getValue().textBody())
        .contains("http://localhost:3001/verify-email?token=verify-token");
  }
}
