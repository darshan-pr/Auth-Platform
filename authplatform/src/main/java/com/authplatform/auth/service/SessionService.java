package com.authplatform.auth.service;

import com.authplatform.auth.entity.Session;
import com.authplatform.auth.repository.SessionRepository;
import com.authplatform.common.crypto.SecureTokenGenerator;
import com.authplatform.common.crypto.TokenHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SessionService {
  private static final Duration PREVIOUS_REFRESH_GRACE = Duration.ofSeconds(10);

  private final SessionRepository repository;
  private final SecureTokenGenerator generator;
  private final TokenHasher hasher;
  private final StringRedisTemplate redis;
  private final Duration ttl;
  private final Duration accessTtl;
  private final Duration accountTtl;
  private final Duration accountAccessTtl;

  public SessionService(
      SessionRepository repository,
      SecureTokenGenerator generator,
      TokenHasher hasher,
      StringRedisTemplate redis,
      @Value("${authplatform.jwt.refresh-token-ttl}") Duration ttl,
      @Value("${authplatform.jwt.access-token-ttl}") Duration accessTtl,
      @Value("${authplatform.jwt.account-refresh-token-ttl}") Duration accountTtl,
      @Value("${authplatform.jwt.account-access-token-ttl}") Duration accountAccessTtl) {
    this.repository = repository;
    this.generator = generator;
    this.hasher = hasher;
    this.redis = redis;
    this.ttl = ttl;
    this.accessTtl = accessTtl;
    this.accountTtl = accountTtl;
    this.accountAccessTtl = accountAccessTtl;
  }

  @Transactional
  public StartedSession startForAccount(UUID accountId, String ip, String agent) {
    return start(
        Session.forAccount(
            accountId,
            "",
            Instant.now().plus(accountTtl),
            accountAccessTtl.toSeconds(),
            ip,
            agent));
  }

  @Transactional
  public StartedSession startForAppUser(UUID userId, String ip, String agent) {
    return startForAppUser(userId, null, null, ip, agent);
  }

  @Transactional
  public StartedSession startForAppUser(
      UUID userId,
      Integer accessTokenTtlSeconds,
      Integer refreshTokenTtlSeconds,
      String ip,
      String agent) {
    Duration sessionAccessTtl =
        accessTokenTtlSeconds == null
            ? accessTtl
            : Duration.ofSeconds(accessTokenTtlSeconds.longValue());
    Duration sessionRefreshTtl =
        refreshTokenTtlSeconds == null
            ? ttl
            : Duration.ofSeconds(refreshTokenTtlSeconds.longValue());
    return start(
        Session.forAppUser(
            userId,
            "",
            Instant.now().plus(sessionRefreshTtl),
            sessionAccessTtl.toSeconds(),
            ip,
            agent));
  }

  private StartedSession start(Session session) {
    String raw = generator.generate();
    session.rotate("", hasher.hash(raw), Instant.now());
    return new StartedSession(repository.save(session), raw);
  }

  @Transactional(noRollbackFor = ApiException.class)
  public RotatedSession rotate(String raw) {
    String hash = hasher.hash(raw);
    Session session =
        repository.findByRefreshTokenHashForUpdate(hash).orElseGet(() -> reuseSession(hash));
    if (session.getRevokedAt() != null || session.getExpiresAt().isBefore(Instant.now()))
      throw new ApiException(ErrorCode.TOKEN_INVALID);
    String next = generator.generate();
    session.rotate(hash, hasher.hash(next), Instant.now());
    return new RotatedSession(session, next);
  }

  @Transactional
  public Session require(String raw) {
    String hash = hasher.hash(raw);
    Session session =
        repository
            .findByRefreshTokenHash(hash)
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    if (session.getRevokedAt() != null || session.getExpiresAt().isBefore(Instant.now()))
      throw new ApiException(ErrorCode.TOKEN_INVALID);
    return session;
  }

  @Transactional
  public void revoke(String raw) {
    repository.findByRefreshTokenHash(hasher.hash(raw)).ifPresent(this::revokeSession);
  }

  @Transactional
  public void revokeAllForAccount(UUID id) {
    revokeAll(repository.findAllByAccountIdAndRevokedAtIsNull(id));
  }

  @Transactional
  public void revokeAllForAppUser(UUID id) {
    revokeAll(repository.findAllByAppUserIdAndRevokedAtIsNull(id));
  }

  @Transactional(readOnly = true)
  public List<SessionView> accountSessions(UUID accountId, String currentSessionId) {
    Instant now = Instant.now();
    return repository.findAllByAccountIdAndRevokedAtIsNull(accountId).stream()
        .filter(session -> session.getExpiresAt().isAfter(now))
        .sorted(Comparator.comparing(Session::getLastActiveAt).reversed())
        .map(session -> view(session, currentSessionId))
        .toList();
  }

  @Transactional
  public void revokeAccountSession(UUID accountId, UUID sessionId) {
    Session session =
        repository
            .findById(sessionId)
            .filter(value -> accountId.equals(value.getAccountId()))
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    revokeSession(session);
  }

  @Transactional(readOnly = true)
  public List<SessionView> appUserSessions(UUID appUserId, String currentSessionId) {
    Instant now = Instant.now();
    return repository.findAllByAppUserIdAndRevokedAtIsNull(appUserId).stream()
        .filter(session -> session.getExpiresAt().isAfter(now))
        .sorted(Comparator.comparing(Session::getLastActiveAt).reversed())
        .map(session -> view(session, currentSessionId))
        .toList();
  }

  @Transactional
  public void revokeAppUserSession(UUID appUserId, UUID sessionId) {
    Session session =
        repository
            .findById(sessionId)
            .filter(value -> appUserId.equals(value.getAppUserId()))
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    revokeSession(session);
  }

  public Duration accessTokenTtl(Session session) {
    if (session.getAccountId() != null) return accountAccessTtl;
    Long configured = session.getAccessTokenTtlSeconds();
    return configured == null ? accessTtl : Duration.ofSeconds(configured);
  }

  public long refreshTokenTtlSeconds(Session session) {
    return Math.max(1, Duration.between(Instant.now(), session.getExpiresAt()).toSeconds());
  }

  private void revokeAll(List<Session> sessions) {
    sessions.forEach(this::revokeSession);
  }

  private void revokeSession(Session session) {
    session.revoke(Instant.now());
    redis
        .opsForValue()
        .set("authplatform:revoked:sid:" + session.getId(), "1", accessTokenTtl(session));
  }

  private SessionView view(Session session, String currentSessionId) {
    return new SessionView(
        session.getId(),
        session.getIpAddress(),
        session.getUserAgent(),
        session.getCreatedAt(),
        session.getLastActiveAt(),
        session.getExpiresAt(),
        session.getId().toString().equals(currentSessionId));
  }

  private Session reuseSession(String hash) {
    Session session =
        repository
            .findByPreviousRefreshHash(hash)
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    if (session.getLastActiveAt().isAfter(Instant.now().minus(PREVIOUS_REFRESH_GRACE))) {
      throw new ApiException(ErrorCode.REFRESH_IN_PROGRESS);
    }
    revokeSession(session);
    throw new ApiException(ErrorCode.TOKEN_INVALID, "Refresh token reuse detected");
  }

  public record StartedSession(Session session, String rawRefreshToken) {}

  public record RotatedSession(Session session, String rawRefreshToken) {}

  public record SessionView(
      UUID id,
      String ipAddress,
      String userAgent,
      Instant createdAt,
      Instant lastActiveAt,
      Instant expiresAt,
      boolean current) {}
}
