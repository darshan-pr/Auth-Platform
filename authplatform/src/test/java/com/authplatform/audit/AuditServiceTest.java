package com.authplatform.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class AuditServiceTest {
  @AfterEach
  void clear() {
    RequestContextHolder.resetRequestAttributes();
  }

  @Test
  void recordsRequestContextAndFallsBackToTheRemoteAddress() {
    AuditLogRepository repository = mock(AuditLogRepository.class);
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/console/auth/refresh");
    request.setRemoteAddr("203.0.113.9");
    request.addHeader("User-Agent", "JUnit/1.0");
    RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

    new AuditService(repository, false).recordAccount("TOKEN_REFRESHED", UUID.randomUUID(), null);

    ArgumentCaptor<AuditLog> saved = ArgumentCaptor.forClass(AuditLog.class);
    verify(repository).save(saved.capture());
    assertThat(saved.getValue().getIpAddress()).isEqualTo("203.0.113.9");
    assertThat(saved.getValue().getMetadata())
        .containsEntry("method", "POST")
        .containsEntry("path", "/api/console/auth/refresh")
        .containsEntry("userAgent", "JUnit/1.0");
  }

  @Test
  void mergesCallerMetadataAndWorksOutsideARequest() {
    AuditLogRepository repository = mock(AuditLogRepository.class);

    new AuditService(repository, false)
        .recordAppChange("APP_USERS_INVITED", UUID.randomUUID(), UUID.randomUUID(), Map.of("invited", 3));

    ArgumentCaptor<AuditLog> saved = ArgumentCaptor.forClass(AuditLog.class);
    verify(repository).save(saved.capture());
    assertThat(saved.getValue().getMetadata()).containsEntry("invited", 3);
    assertThat(saved.getValue().getIpAddress()).isNull();
  }
}
