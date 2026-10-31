package com.authplatform.sa.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.audit.AuditLogRepository;
import com.authplatform.audit.AuditService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.crypto.SecureTokenGenerator;
import com.authplatform.common.crypto.TokenHasher;
import com.authplatform.notification.EmailMessage;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.sa.dto.SaDtos;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AccountRepository;
import com.authplatform.user.repository.AppUserRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class SaServiceTest {
  @Test
  void updateUserStatusSendsAppBrandedNotification() {
    UUID appId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    App app = mock(App.class);
    AppRepository apps = mock(AppRepository.class);
    AppUserRepository users = mock(AppUserRepository.class);
    EmailSender email = mock(EmailSender.class);
    AppUser user = mock(AppUser.class);
    when(app.getName()).thenReturn("Workspace");
    when(apps.findById(appId)).thenReturn(Optional.of(app));
    when(users.findByAppIdAndId(appId, userId)).thenReturn(Optional.of(user));
    when(user.getStatus()).thenReturn("ACTIVE");
    when(user.getName()).thenReturn("Casey");
    when(user.getEmail()).thenReturn("user@example.com");
    SaService service =
        new SaService(
            mock(AccountRepository.class),
            apps,
            users,
            mock(AuditLogRepository.class),
            mock(PasswordHasher.class),
            mock(SecureTokenGenerator.class),
            mock(TokenHasher.class),
            mock(SessionService.class),
            mock(AuditService.class),
            email,
            new EmailTemplateService(""));

    service.updateUser(
        appId,
        userId,
        new SaDtos.UpdateAppUserRequest(null, "BLOCKED", null, null),
        actorId,
        "127.0.0.1");

    ArgumentCaptor<EmailMessage> message = ArgumentCaptor.forClass(EmailMessage.class);
    verify(email).send(message.capture());
    assertThat(message.getValue().fromName()).isEqualTo("Workspace");
    assertThat(message.getValue().textBody()).contains("Status: blocked");
  }

  @Test
  void updateUserRevokesSessionsWhenEmailVerificationIsRemoved() {
    UUID appId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    AppRepository apps = mock(AppRepository.class);
    AppUserRepository users = mock(AppUserRepository.class);
    SessionService sessions = mock(SessionService.class);
    AppUser user = mock(AppUser.class);
    when(apps.findById(appId)).thenReturn(Optional.of(mock(App.class)));
    when(users.findByAppIdAndId(appId, userId)).thenReturn(Optional.of(user));
    when(user.getStatus()).thenReturn("ACTIVE");
    when(user.getEmail()).thenReturn("user@example.com");
    when(user.isEmailVerified()).thenReturn(true);
    SaService service =
        new SaService(
            mock(AccountRepository.class),
            apps,
            users,
            mock(AuditLogRepository.class),
            mock(PasswordHasher.class),
            mock(SecureTokenGenerator.class),
            mock(TokenHasher.class),
            sessions,
            mock(AuditService.class),
            mock(EmailSender.class),
            new EmailTemplateService(""));

    service.updateUser(
        appId,
        userId,
        new SaDtos.UpdateAppUserRequest(null, null, false, null),
        actorId,
        "127.0.0.1");

    verify(user).updateBySa(null, "ACTIVE", false, null);
    verify(sessions).revokeAllForAppUser(userId);
  }
}
