package com.authplatform.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authplatform.auth.entity.Session;
import com.authplatform.auth.repository.SessionRepository;
import com.authplatform.common.crypto.SecureTokenGenerator;
import com.authplatform.common.crypto.TokenHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import org.mockito.ArgumentCaptor;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

class SessionServiceTest {
  @Test
  void refreshPrecheckUsesAnIsolatedReadTransaction() throws Exception {
    Transactional transaction =
        SessionService.class
            .getMethod("require", String.class)
            .getAnnotation(Transactional.class);

    assertThat(transaction.propagation()).isEqualTo(Propagation.REQUIRES_NEW);
  }

  @Test
  void startupInitializerRestoresTheRevocationCache() {
    SessionService sessions = mock(SessionService.class);

    new SessionRevocationCacheInitializer(sessions).afterSingletonsInstantiated();

    verify(sessions).restoreRevocationCache();
  }

  @Test
  void startupRestoresRevocationMarkersForUnexpiredAccessTokens() {
    SessionRepository repository = mock(SessionRepository.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    ValueOperations<String, String> values = mock(ValueOperations.class);
    Session session = mock(Session.class);
    UUID sessionId = UUID.randomUUID();
    Instant revokedAt = Instant.now().minusSeconds(10);
    when(repository.findAllByRevokedAtAfter(any(Instant.class))).thenReturn(List.of(session));
    when(session.getRevokedAt()).thenReturn(revokedAt);
    when(session.getId()).thenReturn(sessionId);
    when(session.getAccessTokenTtlSeconds()).thenReturn(300L);
    when(redis.opsForValue()).thenReturn(values);
    SessionService service =
        new SessionService(
            repository,
            mock(SecureTokenGenerator.class),
            mock(TokenHasher.class),
            redis,
            mock(SessionReplayRevocationService.class),
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));

    service.restoreRevocationCache();

    ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
    verify(values)
        .set(eq("authplatform:revoked:sid:" + sessionId), eq("1"), ttl.capture());
    assertThat(ttl.getValue())
        .isBetween(Duration.ofSeconds(289), Duration.ofSeconds(302));
  }

  @Test
  void accountSessionsUsePlatformTokenLifetimes() {
    SessionRepository repository = mock(SessionRepository.class);
    SecureTokenGenerator generator = mock(SecureTokenGenerator.class);
    TokenHasher hasher = mock(TokenHasher.class);
    when(generator.generate()).thenReturn("refresh-token");
    when(hasher.hash("refresh-token")).thenReturn("refresh-hash");
    when(repository.save(any(Session.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    SessionService service =
        new SessionService(
            repository,
            generator,
            hasher,
            mock(StringRedisTemplate.class),
            mock(SessionReplayRevocationService.class),
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));
    Instant before = Instant.now();

    SessionService.StartedSession started =
        service.startForAccount(UUID.randomUUID(), "127.0.0.1", "test-agent");

    assertThat(started.session().getAccessTokenTtlSeconds()).isEqualTo(1_800L);
    assertThat(service.accessTokenTtl(started.session())).isEqualTo(Duration.ofMinutes(30));
    assertThat(started.session().getExpiresAt())
        .isBetween(before.plusSeconds(172_799), before.plusSeconds(172_801));
  }

  @Test
  void appUserSessionsStoreTheirConfiguredTokenLifetimes() {
    SessionRepository repository = mock(SessionRepository.class);
    SecureTokenGenerator generator = mock(SecureTokenGenerator.class);
    TokenHasher hasher = mock(TokenHasher.class);
    when(generator.generate()).thenReturn("refresh-token");
    when(hasher.hash("refresh-token")).thenReturn("refresh-hash");
    when(repository.save(any(Session.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    SessionService service =
        new SessionService(
            repository,
            generator,
            hasher,
            mock(StringRedisTemplate.class),
            mock(SessionReplayRevocationService.class),
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));
    Instant before = Instant.now();

    SessionService.StartedSession started =
        service.startForAppUser(UUID.randomUUID(), 300, 86_400, "127.0.0.1", "test-agent");

    assertThat(started.session().getAccessTokenTtlSeconds()).isEqualTo(300L);
    assertThat(started.session().getExpiresAt())
        .isBetween(before.plusSeconds(86_399), before.plusSeconds(86_401));
  }

  @Test
  void appUserSessionsKeepSdkPlatformDefaultLifetimes() {
    SessionRepository repository = mock(SessionRepository.class);
    SecureTokenGenerator generator = mock(SecureTokenGenerator.class);
    TokenHasher hasher = mock(TokenHasher.class);
    when(generator.generate()).thenReturn("refresh-token");
    when(hasher.hash("refresh-token")).thenReturn("refresh-hash");
    when(repository.save(any(Session.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    SessionService service =
        new SessionService(
            repository,
            generator,
            hasher,
            mock(StringRedisTemplate.class),
            mock(SessionReplayRevocationService.class),
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));
    Instant before = Instant.now();

    SessionService.StartedSession started =
        service.startForAppUser(UUID.randomUUID(), null, null, "127.0.0.1", "test-agent");

    assertThat(started.session().getAccessTokenTtlSeconds()).isEqualTo(900L);
    assertThat(started.session().getExpiresAt())
        .isBetween(before.plusSeconds(2_591_999), before.plusSeconds(2_592_001));
  }

  @Test
  void reuseOfPreviousRefreshTokenRevokesTheSession() throws Exception {
    SessionRepository repository = mock(SessionRepository.class);
    TokenHasher hasher = mock(TokenHasher.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    SessionReplayRevocationService replayRevocations =
        mock(SessionReplayRevocationService.class);
    Session session = mock(Session.class);
    UUID sessionId = UUID.randomUUID();
    when(hasher.hash("previous-token")).thenReturn("previous-hash");
    when(repository.findByRefreshTokenHashForUpdate("previous-hash")).thenReturn(Optional.empty());
    when(repository.findByUsedRefreshTokenHash("previous-hash")).thenReturn(Optional.of(session));
    when(session.getId()).thenReturn(sessionId);
    when(session.getPreviousRefreshHash()).thenReturn("previous-hash");
    when(session.getLastActiveAt()).thenReturn(Instant.now().minusSeconds(30));
    when(session.getAccessTokenTtlSeconds()).thenReturn(300L);
    SessionService service =
        new SessionService(
            repository,
            mock(SecureTokenGenerator.class),
            hasher,
            redis,
            replayRevocations,
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));

    assertThrows(ApiException.class, () -> service.rotate("previous-token"));

    verify(replayRevocations).revoke(sessionId, Duration.ofSeconds(300));
    assertThat(
            SessionService.class
                .getMethod("rotate", String.class)
                .getAnnotation(Transactional.class)
                .noRollbackFor())
        .contains(ApiException.class);
  }

  @Test
  void recentlyRotatedRefreshTokenIsRetryableAndDoesNotRevokeTheSession() {
    SessionRepository repository = mock(SessionRepository.class);
    TokenHasher hasher = mock(TokenHasher.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    SessionReplayRevocationService replayRevocations =
        mock(SessionReplayRevocationService.class);
    Session session = mock(Session.class);
    when(hasher.hash("previous-token")).thenReturn("previous-hash");
    when(repository.findByRefreshTokenHashForUpdate("previous-hash")).thenReturn(Optional.empty());
    when(repository.findByUsedRefreshTokenHash("previous-hash")).thenReturn(Optional.of(session));
    when(session.getPreviousRefreshHash()).thenReturn("previous-hash");
    when(session.getLastActiveAt()).thenReturn(Instant.now().minusSeconds(1));
    SessionService service =
        new SessionService(
            repository,
            mock(SecureTokenGenerator.class),
            hasher,
            redis,
            replayRevocations,
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));

    ApiException error = assertThrows(ApiException.class, () -> service.rotate("previous-token"));

    assertThat(error.code()).isEqualTo(ErrorCode.REFRESH_IN_PROGRESS);
    verify(replayRevocations, never()).revoke(any(), any());
  }

  @Test
  void replayOfAnOlderRefreshTokenRevokesTheFamilyAfterMultipleRotations() {
    SessionRepository repository = mock(SessionRepository.class);
    TokenHasher hasher = mock(TokenHasher.class);
    SessionReplayRevocationService replayRevocations =
        mock(SessionReplayRevocationService.class);
    Session session = mock(Session.class);
    UUID sessionId = UUID.randomUUID();
    when(hasher.hash("old-token")).thenReturn("old-hash");
    when(repository.findByRefreshTokenHashForUpdate("old-hash")).thenReturn(Optional.empty());
    when(repository.findByUsedRefreshTokenHash("old-hash")).thenReturn(Optional.of(session));
    when(session.getId()).thenReturn(sessionId);
    when(session.getPreviousRefreshHash()).thenReturn("newer-hash");
    when(session.getLastActiveAt()).thenReturn(Instant.now().minusSeconds(1));
    when(session.getAccessTokenTtlSeconds()).thenReturn(300L);
    SessionService service =
        new SessionService(
            repository,
            mock(SecureTokenGenerator.class),
            hasher,
            mock(StringRedisTemplate.class),
            replayRevocations,
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));

    assertThrows(ApiException.class, () -> service.rotate("old-token"));

    verify(repository).findByUsedRefreshTokenHash("old-hash");
    verify(replayRevocations).revoke(sessionId, Duration.ofSeconds(300));
  }

  @Test
  void revokedAccountSessionRemainsBlockedForItsAccessLifetime() {
    SessionRepository repository = mock(SessionRepository.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    ValueOperations<String, String> values = mock(ValueOperations.class);
    Session session = mock(Session.class);
    UUID accountId = UUID.randomUUID();
    UUID sessionId = UUID.randomUUID();
    when(repository.findById(sessionId)).thenReturn(Optional.of(session));
    when(session.getAccountId()).thenReturn(accountId);
    when(session.getId()).thenReturn(sessionId);
    when(session.getAccessTokenTtlSeconds()).thenReturn(300L);
    when(redis.opsForValue()).thenReturn(values);
    SessionService service =
        new SessionService(
            repository,
            mock(SecureTokenGenerator.class),
            mock(TokenHasher.class),
            redis,
            mock(SessionReplayRevocationService.class),
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));

    service.revokeAccountSession(accountId, sessionId);

    verify(values)
        .set("authplatform:revoked:sid:" + sessionId, "1", Duration.ofMinutes(30));
  }

  @Test
  void accountCannotRevokeAnotherAccountsSession() {
    SessionRepository repository = mock(SessionRepository.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    Session session = mock(Session.class);
    UUID sessionId = UUID.randomUUID();
    when(repository.findById(sessionId)).thenReturn(Optional.of(session));
    when(session.getAccountId()).thenReturn(UUID.randomUUID());

    SessionService service =
        new SessionService(
            repository,
            mock(SecureTokenGenerator.class),
            mock(TokenHasher.class),
            redis,
            mock(SessionReplayRevocationService.class),
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));

    assertThrows(
        ApiException.class, () -> service.revokeAccountSession(UUID.randomUUID(), sessionId));
    verify(session, never()).revoke(any());
  }

  @Test
  void appUserCannotRevokeAnotherUsersSession() {
    SessionRepository repository = mock(SessionRepository.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    Session session = mock(Session.class);
    UUID sessionId = UUID.randomUUID();
    when(repository.findById(sessionId)).thenReturn(Optional.of(session));
    when(session.getAppUserId()).thenReturn(UUID.randomUUID());

    SessionService service =
        new SessionService(
            repository,
            mock(SecureTokenGenerator.class),
            mock(TokenHasher.class),
            redis,
            mock(SessionReplayRevocationService.class),
            Duration.ofDays(30),
            Duration.ofMinutes(15),
            Duration.ofHours(48),
            Duration.ofMinutes(30));

    assertThrows(
        ApiException.class, () -> service.revokeAppUserSession(UUID.randomUUID(), sessionId));
    verify(session, never()).revoke(any());
  }
}
