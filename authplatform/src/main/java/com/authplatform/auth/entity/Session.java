package com.authplatform.auth.entity;

import com.authplatform.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "sessions")
public class Session extends BaseEntity {
  @Column(name = "account_id")
  private UUID accountId;

  @Column(name = "app_user_id")
  private UUID appUserId;

  @Column(name = "refresh_token_hash", nullable = false, unique = true, length = 64)
  private String refreshTokenHash;

  @Column(name = "previous_refresh_hash", length = 64)
  private String previousRefreshHash;

  @Column(name = "ip_address")
  private String ipAddress;

  @Column(name = "user_agent")
  private String userAgent;

  @Column(name = "last_active_at", nullable = false)
  private Instant lastActiveAt;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(name = "access_token_ttl_seconds")
  private Long accessTokenTtlSeconds;

  @Column(name = "revoked_at")
  private Instant revokedAt;

  protected Session() {}

  public static Session forAccount(
      UUID id,
      String hash,
      Instant expires,
      long accessTokenTtlSeconds,
      String ip,
      String agent) {
    Session s = new Session();
    s.accountId = id;
    s.refreshTokenHash = hash;
    s.expiresAt = expires;
    s.accessTokenTtlSeconds = accessTokenTtlSeconds;
    s.lastActiveAt = Instant.now();
    s.ipAddress = ip;
    s.userAgent = agent;
    return s;
  }

  public static Session forAppUser(
      UUID id,
      String hash,
      Instant expires,
      long accessTokenTtlSeconds,
      String ip,
      String agent) {
    Session s = forAccount(null, hash, expires, accessTokenTtlSeconds, ip, agent);
    s.accountId = null;
    s.appUserId = id;
    return s;
  }

  public void rotate(String oldHash, String newHash, Instant now) {
    previousRefreshHash = oldHash;
    refreshTokenHash = newHash;
    lastActiveAt = now;
  }

  public void revoke(Instant now) {
    revokedAt = now;
  }

  public UUID getAccountId() {
    return accountId;
  }

  public UUID getAppUserId() {
    return appUserId;
  }

  public String getRefreshTokenHash() {
    return refreshTokenHash;
  }

  public String getPreviousRefreshHash() {
    return previousRefreshHash;
  }

  public Instant getExpiresAt() {
    return expiresAt;
  }

  public Long getAccessTokenTtlSeconds() {
    return accessTokenTtlSeconds;
  }

  public String getIpAddress() {
    return ipAddress;
  }

  public String getUserAgent() {
    return userAgent;
  }

  public Instant getLastActiveAt() {
    return lastActiveAt;
  }

  public Instant getRevokedAt() {
    return revokedAt;
  }
}
