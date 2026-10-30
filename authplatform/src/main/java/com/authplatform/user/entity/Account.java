package com.authplatform.user.entity;

import com.authplatform.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

@Entity
@Table(name = "accounts")
public class Account extends BaseEntity {
  @Column(nullable = false, length = 320)
  private String email;

  @Column(name = "password_hash", nullable = false)
  private String passwordHash;

  @Column(nullable = false, length = 120)
  private String name;

  @Column(name = "email_verified", nullable = false)
  private boolean emailVerified;

  @Enumerated(EnumType.STRING)
  @Column(name = "platform_role", nullable = false)
  private PlatformRole platformRole;

  @Column(nullable = false)
  private String status;

  @Column(name = "mfa_required", nullable = false)
  private boolean mfaRequired = true;

  @Column(name = "mfa_enabled", nullable = false)
  private boolean mfaEnabled;

  @Column(name = "mfa_secret", length = 512)
  private String mfaSecret;

  protected Account() {}

  public static Account register(String email, String passwordHash, String name) {
    Account a = new Account();
    a.email = email;
    a.passwordHash = passwordHash;
    a.name = name;
    a.platformRole = PlatformRole.USER;
    a.status = "ACTIVE";
    return a;
  }

  public static Account registerSa(String email, String passwordHash, String name) {
    Account account = register(email, passwordHash, name);
    account.platformRole = PlatformRole.SA;
    account.emailVerified = true;
    return account;
  }

  public void updateBySa(String name, String status, PlatformRole role, String passwordHash) {
    if (name != null) this.name = name.trim();
    if (status != null) this.status = status;
    if (role != null) this.platformRole = role;
    if (passwordHash != null) this.passwordHash = passwordHash;
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

  public PlatformRole getPlatformRole() {
    return platformRole;
  }

  public String getStatus() {
    return status;
  }

  public boolean isMfaRequired() {
    return mfaRequired;
  }

  public boolean isMfaEnabled() {
    return mfaEnabled;
  }

  public String getMfaSecret() {
    return mfaSecret;
  }
}
