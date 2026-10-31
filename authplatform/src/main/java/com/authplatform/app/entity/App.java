package com.authplatform.app.entity;

import com.authplatform.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "apps")
public class App extends BaseEntity {
  @Column(name = "owner_account_id", nullable = false)
  private UUID ownerAccountId;

  @Column(nullable = false, length = 100)
  private String name;

  @Column(name = "publishable_key", nullable = false, unique = true)
  private String publishableKey;

  @Column(name = "secret_key_hash", nullable = false, length = 64)
  private String secretKeyHash;

  @Column(name = "secret_key_hint", nullable = false, length = 12)
  private String secretKeyHint;

  @JdbcTypeCode(SqlTypes.ARRAY)
  @Column(name = "allowed_origins", nullable = false, columnDefinition = "text[]")
  private String[] allowedOrigins;

  @Column(name = "verify_email_url")
  private String verifyEmailUrl;

  @Column(name = "icon_url", columnDefinition = "text")
  private String iconUrl;

  @Column(name = "icon_data", columnDefinition = "bytea")
  private byte[] iconData;

  @Column(name = "icon_content_type", length = 32)
  private String iconContentType;

  @Column(name = "icon_position_x", nullable = false)
  private int iconPositionX = 50;

  @Column(name = "icon_position_y", nullable = false)
  private int iconPositionY = 50;

  @Column(name = "icon_zoom_percent", nullable = false)
  private int iconZoomPercent = 100;

  @Column(name = "reset_password_url")
  private String resetPasswordUrl;

  @Column(name = "require_email_verification", nullable = false)
  private boolean requireEmailVerification = true;

  @Column(nullable = false)
  private String status = "ACTIVE";

  @Column(name = "mfa_required", nullable = false)
  private boolean mfaRequired;

  @Column(name = "access_token_ttl_seconds")
  private Integer accessTokenTtlSeconds;

  @Column(name = "refresh_token_ttl_seconds")
  private Integer refreshTokenTtlSeconds;

  protected App() {}

  public static App create(
      UUID owner,
      String name,
      List<String> origins,
      String publishable,
      String hash,
      String hint,
      String verifyUrl,
      String resetUrl) {
    return create(owner, name, origins, publishable, hash, hint, verifyUrl, resetUrl, false, null, null);
  }

  public static App create(
      UUID owner,
      String name,
      List<String> origins,
      String publishable,
      String hash,
      String hint,
      String verifyUrl,
      String resetUrl,
      Boolean mfaRequired) {
    return create(
        owner, name, origins, publishable, hash, hint, verifyUrl, resetUrl, mfaRequired, null, null);
  }

  public static App create(
      UUID owner,
      String name,
      List<String> origins,
      String publishable,
      String hash,
      String hint,
      String verifyUrl,
      String resetUrl,
      Boolean mfaRequired,
      Integer accessTokenTtlSeconds,
      Integer refreshTokenTtlSeconds) {
    App a = new App();
    a.ownerAccountId = owner;
    a.name = name;
    a.allowedOrigins = origins.toArray(String[]::new);
    a.publishableKey = publishable;
    a.secretKeyHash = hash;
    a.secretKeyHint = hint;
    a.verifyEmailUrl = verifyUrl;
    a.resetPasswordUrl = resetUrl;
    a.mfaRequired = Boolean.TRUE.equals(mfaRequired);
    a.accessTokenTtlSeconds = accessTokenTtlSeconds;
    a.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    return a;
  }

  public void update(
      String name,
      List<String> origins,
      String verifyUrl,
      String resetUrl,
      Boolean requireVerification,
      String status) {
    update(name, origins, verifyUrl, resetUrl, requireVerification, status, null, null, null, null);
  }

  public void update(
      String name,
      List<String> origins,
      String verifyUrl,
      String resetUrl,
      Boolean requireVerification,
      String status,
      Boolean mfaRequired) {
    update(
        name,
        origins,
        verifyUrl,
        resetUrl,
        requireVerification,
        status,
        mfaRequired,
        null,
        null,
        null);
  }

  public void update(
      String name,
      List<String> origins,
      String verifyUrl,
      String resetUrl,
      Boolean requireVerification,
      String status,
      Boolean mfaRequired,
      Integer accessTokenTtlSeconds,
      Integer refreshTokenTtlSeconds,
      Boolean usePlatformTokenTtls) {
    if (name != null) this.name = name;
    if (origins != null) this.allowedOrigins = origins.toArray(String[]::new);
    if (verifyUrl != null) this.verifyEmailUrl = verifyUrl;
    if (resetUrl != null) this.resetPasswordUrl = resetUrl;
    if (requireVerification != null) this.requireEmailVerification = requireVerification;
    if (status != null) this.status = status;
    if (mfaRequired != null) this.mfaRequired = mfaRequired;
    if (Boolean.TRUE.equals(usePlatformTokenTtls)) {
      this.accessTokenTtlSeconds = null;
      this.refreshTokenTtlSeconds = null;
    } else if (accessTokenTtlSeconds != null && refreshTokenTtlSeconds != null) {
      this.accessTokenTtlSeconds = accessTokenTtlSeconds;
      this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }
  }

  public void rotateSecret(String hash, String hint) {
    secretKeyHash = hash;
    secretKeyHint = hint;
  }

  public void setIconUrl(String url) {
    iconUrl = url;
    iconData = null;
    iconContentType = null;
  }

  public void setIconData(byte[] data, String contentType) {
    iconUrl = null;
    iconData = Arrays.copyOf(data, data.length);
    iconContentType = contentType;
  }

  public void clearIcon() {
    iconUrl = null;
    iconData = null;
    iconContentType = null;
    iconPositionX = 50;
    iconPositionY = 50;
    iconZoomPercent = 100;
  }

  public void updateIconCrop(Integer positionX, Integer positionY, Integer zoomPercent) {
    if (positionX != null) iconPositionX = positionX;
    if (positionY != null) iconPositionY = positionY;
    if (zoomPercent != null) iconZoomPercent = zoomPercent;
  }

  public UUID getOwnerAccountId() {
    return ownerAccountId;
  }

  public String getName() {
    return name;
  }

  public String getPublishableKey() {
    return publishableKey;
  }

  public String getSecretKeyHash() {
    return secretKeyHash;
  }

  public String getSecretKeyHint() {
    return secretKeyHint;
  }

  public List<String> getAllowedOrigins() {
    return allowedOrigins == null ? List.of() : Arrays.asList(allowedOrigins);
  }

  public String getVerifyEmailUrl() {
    return verifyEmailUrl;
  }

  public String getIconUrl() {
    return iconUrl;
  }

  public byte[] getIconData() {
    return iconData == null ? null : Arrays.copyOf(iconData, iconData.length);
  }

  public String getIconContentType() {
    return iconContentType;
  }

  public String getIconDataUrl() {
    if (iconData == null || iconContentType == null) return null;
    return "data:" + iconContentType + ";base64," + java.util.Base64.getEncoder().encodeToString(iconData);
  }

  public int getIconPositionX() {
    return iconPositionX;
  }

  public int getIconPositionY() {
    return iconPositionY;
  }

  public int getIconZoomPercent() {
    return iconZoomPercent;
  }

  public String getResetPasswordUrl() {
    return resetPasswordUrl;
  }

  public boolean isRequireEmailVerification() {
    return requireEmailVerification;
  }

  public String getStatus() {
    return status;
  }

  public boolean isMfaRequired() {
    return mfaRequired;
  }

  public Integer getAccessTokenTtlSeconds() {
    return accessTokenTtlSeconds;
  }

  public Integer getRefreshTokenTtlSeconds() {
    return refreshTokenTtlSeconds;
  }
}
