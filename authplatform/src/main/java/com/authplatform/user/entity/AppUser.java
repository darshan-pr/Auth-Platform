package com.authplatform.user.entity;

import com.authplatform.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "app_users")
public class AppUser extends BaseEntity {
  @Column(name = "app_id", nullable = false)
  private UUID appId;

  @Column(nullable = false, length = 320)
  private String email;

  @Column(name = "password_hash", nullable = false)
  private String passwordHash;

  @Column(nullable = false, length = 120)
  private String name;

  @Column(name = "email_verified", nullable = false)
  private boolean emailVerified;

  @Column(nullable = false)
  private String status;

  @Column(name = "last_login_at")
  private Instant lastLoginAt;

  @Column(name = "invited_at")
  private Instant invitedAt;

  @Column(name = "mfa_enabled", nullable = false)
  private boolean mfaEnabled;

  @Column(name = "mfa_secret", length = 512)
  private String mfaSecret;

  protected AppUser() {}

  public static AppUser register(UUID appId, String email, String passwordHash, String name) {
    AppUser u = new AppUser();
    u.appId = appId;
    u.email = email;
    u.passwordHash = passwordHash;
    u.name = name;
    u.status = "ACTIVE";
    return u;
  }

  public static AppUser invite(UUID appId, String email, String passwordHash, String name) {
    AppUser u = register(appId, email, passwordHash, name);
    u.invitedAt = Instant.now();
    return u;
  }

  /** Replaces the temporary password of a user who has not signed in yet. */
  public void reinvite(String passwordHash) {
    this.passwordHash = passwordHash;
    this.invitedAt = Instant.now();
  }

  public void markEmailVerified() {
    emailVerified = true;
  }

  public void changePassword(String hash) {
    passwordHash = hash;
  }

  public void enableMfa(String encryptedSecret) {
    mfaSecret = encryptedSecret;
    mfaEnabled = true;
  }

  public void updateBySa(String name, String status, Boolean emailVerified, String passwordHash) {
    if (name != null) this.name = name.trim();
    if (status != null) this.status = status;
    if (emailVerified != null) this.emailVerified = emailVerified;
    if (passwordHash != null) this.passwordHash = passwordHash;
  }

  public void markLogin(Instant now) {
    lastLoginAt = now;
  }

  public UUID getAppId() {
    return appId;
  }

  public String getEmail() {
    return email;
  }

  public String getPasswordHash() {
    return passwordHash;
  }

  public String getName() {
    return name;
  }

  public boolean isEmailVerified() {
    return emailVerified;
  }

  public String getStatus() {
    return status;
  }

  public Instant getLastLoginAt() {
    return lastLoginAt;
  }

  public Instant getInvitedAt() {
    return invitedAt;
  }

  /** True from the invitation until the user's first successful sign-in. */
  public boolean isInvited() {
    return invitedAt != null && lastLoginAt == null;
  }

  public boolean isMfaEnabled() {
    return mfaEnabled;
  }

  public String getMfaSecret() {
    return mfaSecret;
  }
}
