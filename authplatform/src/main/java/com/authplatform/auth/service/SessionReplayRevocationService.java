package com.authplatform.auth.service;

import com.authplatform.auth.entity.Session;
import com.authplatform.auth.repository.SessionRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SessionReplayRevocationService {
  private final SessionRepository repository;
  private final StringRedisTemplate redis;

  public SessionReplayRevocationService(
      SessionRepository repository, StringRedisTemplate redis) {
    this.repository = repository;
    this.redis = redis;
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void revoke(UUID sessionId, Duration accessTokenTtl) {
    repository
        .findById(sessionId)
        .ifPresent(
            session -> {
              session.revoke(Instant.now());
              redis
                  .opsForValue()
                  .set("authplatform:revoked:sid:" + session.getId(), "1", accessTokenTtl);
            });
  }
}
