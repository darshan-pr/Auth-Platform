package com.authplatform.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authplatform.auth.entity.Session;
import com.authplatform.auth.repository.SessionRepository;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

class SessionReplayRevocationServiceTest {
  @Test
  void replayRevocationPersistsAndBlocksTheSessionAccessToken() throws Exception {
    SessionRepository repository = mock(SessionRepository.class);
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    ValueOperations<String, String> values = mock(ValueOperations.class);
    Session session = mock(Session.class);
    UUID sessionId = UUID.randomUUID();
    when(repository.findById(sessionId)).thenReturn(Optional.of(session));
    when(session.getId()).thenReturn(sessionId);
    when(redis.opsForValue()).thenReturn(values);
    SessionReplayRevocationService service =
        new SessionReplayRevocationService(repository, redis);

    service.revoke(sessionId, Duration.ofSeconds(300));

    verify(session).revoke(any());
    verify(values)
        .set("authplatform:revoked:sid:" + sessionId, "1", Duration.ofSeconds(300));
    Transactional transaction =
        SessionReplayRevocationService.class
            .getMethod("revoke", UUID.class, Duration.class)
            .getAnnotation(Transactional.class);
    assertThat(transaction.propagation()).isEqualTo(Propagation.REQUIRES_NEW);
  }
}
