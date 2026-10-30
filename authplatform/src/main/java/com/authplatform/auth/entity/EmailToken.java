package com.authplatform.auth.entity;

import com.authplatform.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "email_tokens")
public class EmailToken extends BaseEntity {
  @Column(name = "account_id")
  private UUID accountId;

  @Column(name = "app_user_id")
  private UUID appUserId;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private EmailTokenType type;

  @Column(name = "token_hash", nullable = false, unique = true, length = 64)
  private String tokenHash;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(name = "used_at")
  private Instant usedAt;

  protected EmailToken() {}

  public static EmailToken forAccount(UUID id, EmailTokenType type, String hash, Instant expires) {
    EmailToken t = new EmailToken();
    t.accountId = id;
    t.type = type;
    t.tokenHash = hash;
    t.expiresAt = expires;
    return t;
  }

  public static EmailToken forAppUser(UUID id, EmailTokenType type, String hash, Instant expires) {
    EmailToken t = forAccount(null, type, hash, expires);
    t.appUserId = id;
    return t;
  }

  public boolean isUsable(Instant now) {
    return usedAt == null && expiresAt.isAfter(now);
  }

  public void use(Instant now) {
    usedAt = now;
  }

  public UUID getAccountId() {
    return accountId;
  }

  public UUID getAppUserId() {
    return appUserId;
  }

  public EmailTokenType getType() {
    return type;
  }

  public String getTokenHash() {
    return tokenHash;
  }
}
