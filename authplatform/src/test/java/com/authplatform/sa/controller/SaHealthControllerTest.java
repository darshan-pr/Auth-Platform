package com.authplatform.sa.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.CompositeHealth;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.health.Status;

class SaHealthControllerTest {
  @Test
  void reportsOverallAndComponentStatusWithoutDetails() {
    CompositeHealth composite = mock(CompositeHealth.class);
    when(composite.getStatus()).thenReturn(Status.DOWN);
    when(composite.getComponents())
        .thenReturn(
            Map.of(
                "db", Health.up().withDetail("database", "PostgreSQL").build(),
                "redis", Health.down().build()));
    HealthEndpoint endpoint = mock(HealthEndpoint.class);
    when(endpoint.health()).thenReturn(composite);

    var body = new SaHealthController(endpoint).health().getBody();

    assertThat(body.status()).isEqualTo("DOWN");
    assertThat(body.components())
        .containsEntry("db", new SaHealthController.HealthStatus("UP"))
        .containsEntry("redis", new SaHealthController.HealthStatus("DOWN"));
    assertThat(body.toString()).doesNotContain("PostgreSQL");
  }
}
