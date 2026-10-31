package com.authplatform.sa.controller;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.actuate.health.CompositeHealth;
import org.springframework.boot.actuate.health.HealthComponent;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Dependency health for the SA dashboard. The actuator endpoint is not routed to the backend by the
 * load balancer, and exposing component status publicly would leak infrastructure details.
 */
@RestController
@RequestMapping("/api/sa/health")
public class SaHealthController {
  private final HealthEndpoint health;

  public SaHealthController(HealthEndpoint health) {
    this.health = health;
  }

  @GetMapping
  ResponseEntity<HealthView> health() {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(view(health.health()));
  }

  static HealthView view(HealthComponent result) {
    Map<String, HealthStatus> components = new LinkedHashMap<>();
    if (result instanceof CompositeHealth composite) {
      composite
          .getComponents()
          .forEach((name, component) -> components.put(name, new HealthStatus(status(component))));
    }
    return new HealthView(status(result), components);
  }

  private static String status(HealthComponent component) {
    return component.getStatus().getCode();
  }

  public record HealthStatus(String status) {}

  public record HealthView(String status, Map<String, HealthStatus> components) {}
}
