package com.authplatform.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "audit_logs")
public class AuditLog {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "app_id")
  private UUID appId;

  @Column(name = "actor_account_id")
  private UUID actorAccountId;

  @Column(name = "actor_app_user_id")
  private UUID actorAppUserId;

  @Column(name = "actor_type", nullable = false)
  private String actorType;

  @Column(nullable = false)
  private String action;

  @Column(name = "ip_address")
  private String ipAddress;

  @Column(name = "request_id")
  private String requestId;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(columnDefinition = "jsonb")
  private Map<String, Object> metadata;

  @Column(name = "created_at", nullable = false)
  private Instant createdAt;

  protected AuditLog() {}

  public static AuditLog create(
      String action,
      String actorType,
      UUID accountId,
      UUID appUserId,
      UUID appId,
      String ipAddress,
      String requestId,
      Map<String, Object> metadata) {
    AuditLog log = new AuditLog();
    log.action = action;
    log.actorType = actorType;
    log.actorAccountId = accountId;
    log.actorAppUserId = appUserId;
    log.appId = appId;
    log.ipAddress = ipAddress;
    log.requestId = requestId;
    log.metadata = metadata;
    log.createdAt = Instant.now();
    return log;
  }

  public Long getId() {
    return id;
  }

  public UUID getAppId() {
    return appId;
  }

  public UUID getActorAccountId() {
    return actorAccountId;
  }

  public UUID getActorAppUserId() {
    return actorAppUserId;
  }

  public String getActorType() {
    return actorType;
  }

  public String getAction() {
    return action;
  }

  public String getIpAddress() {
    return ipAddress;
  }

  public String getRequestId() {
    return requestId;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  public Map<String, Object> getMetadata() {
    return metadata;
  }
}
