package com.authplatform.app.service.impl;

import com.authplatform.app.dto.AppDtos;
import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.app.service.AppService;
import com.authplatform.app.service.TokenLifetimePolicy;
import com.authplatform.audit.AuditService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.crypto.SecureTokenGenerator;
import com.authplatform.common.crypto.TokenHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.common.security.RedirectUrlValidator;
import com.authplatform.role.entity.Role;
import com.authplatform.role.service.RoleService;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AppUserRepository;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AppServiceImpl implements AppService {
  private static final int MAX_ICON_DATA_URL_LENGTH = 500_000;
  private static final int MAX_ICON_BYTES = 375_000;

  private final AppRepository apps;
  private final RoleService roles;
  private final SecureTokenGenerator generator;
  private final TokenHasher hasher;
  private final AuditService audit;
  private final AppUserRepository users;
  private final PasswordHasher passwords;
  private final SessionService sessions;
  private final int maxApps;
  private final int maxOrigins;

  public AppServiceImpl(
      AppRepository apps,
      RoleService roles,
      SecureTokenGenerator generator,
      TokenHasher hasher,
      AuditService audit,
      AppUserRepository users,
      PasswordHasher passwords,
      SessionService sessions,
      @Value("${authplatform.limits.max-apps-per-account}") int maxApps,
      @Value("${authplatform.limits.max-origins-per-app}") int maxOrigins) {
    this.apps = apps;
    this.roles = roles;
    this.generator = generator;
    this.hasher = hasher;
    this.audit = audit;
    this.users = users;
    this.passwords = passwords;
    this.sessions = sessions;
    this.maxApps = maxApps;
    this.maxOrigins = maxOrigins;
  }

  @Transactional
  public AppDtos.AppCreatedResponse create(UUID owner, AppDtos.CreateAppRequest request) {
    if (apps.countByOwnerAccountId(owner) >= maxApps)
      throw new ApiException(ErrorCode.APP_LIMIT_REACHED);
    TokenLifetimePolicy.validatePair(
        request.accessTokenTtlSeconds(), request.refreshTokenTtlSeconds());
    List<String> origins = origins(request.allowedOrigins());
    String secret = generator.generateSecretKey();
    App app =
        apps.save(
            App.create(
                owner,
                request.name().trim(),
                origins,
                generator.generatePublishableKey(),
                hasher.hash(secret),
                hint(secret),
                RedirectUrlValidator.validate(request.verifyEmailUrl()),
                RedirectUrlValidator.validate(request.resetPasswordUrl()),
                request.mfaRequired(),
                request.accessTokenTtlSeconds(),
                request.refreshTokenTtlSeconds()));
    Role role = roles.createDefaultRole(app.getId());
    audit.recordAppChange("APP_CREATED", owner, app.getId());
    return new AppDtos.AppCreatedResponse(
        app.getId(),
        app.getName(),
        app.getPublishableKey(),
        secret,
        app.getAllowedOrigins(),
        app.getVerifyEmailUrl(),
        app.isRequireEmailVerification(),
        app.isMfaRequired(),
        app.getStatus(),
        app.getCreatedAt(),
        new AppDtos.RoleSummary(role.getId(), role.getName()),
        app.getAccessTokenTtlSeconds(),
        app.getRefreshTokenTtlSeconds(),
        app.getIconUrl(),
        app.getIconDataUrl(),
        app.getIconPositionX(),
        app.getIconPositionY(),
        app.getIconZoomPercent());
  }

  @Transactional(readOnly = true)
  public List<AppDtos.AppResponse> list(UUID owner, int page, int size) {
    int safeSize = Math.min(Math.max(size, 1), 50);
    return apps.findAllByOwnerAccountId(owner, pageRequest(page, safeSize)).stream()
        .map(app -> response(app, false))
        .toList();
  }

  @Transactional(readOnly = true)
  public List<AppDtos.AppUserView> listUsers(UUID owner, UUID appId, int page, int size) {
    apps.findByIdAndOwnerAccountId(appId, owner)
        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    int safeSize = Math.min(Math.max(size, 1), 100);
    return users.findAllByAppId(appId, pageRequest(page, safeSize)).stream()
        .map(this::userView)
        .toList();
  }

  @Transactional(readOnly = true)
  public AppDtos.AppResponse get(UUID owner, UUID id) {
    return response(
        apps.findByIdAndOwnerAccountId(id, owner)
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND)),
        true);
  }

  @Transactional
  public AppDtos.AppResponse update(UUID owner, UUID id, AppDtos.UpdateAppRequest request) {
    App app =
        apps.findByIdAndOwnerAccountId(id, owner)
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    TokenLifetimePolicy.validateUpdate(
        request.accessTokenTtlSeconds(),
        request.refreshTokenTtlSeconds(),
        request.usePlatformTokenTtls());
    if (request.allowedOrigins() != null) origins(request.allowedOrigins());
    String verifyEmailUrl = RedirectUrlValidator.validate(request.verifyEmailUrl());
    String resetPasswordUrl = RedirectUrlValidator.validate(request.resetPasswordUrl());
    app.update(
        request.name(),
        request.allowedOrigins(),
        verifyEmailUrl,
        resetPasswordUrl,
        request.requireEmailVerification(),
        request.status(),
        request.mfaRequired(),
        request.accessTokenTtlSeconds(),
        request.refreshTokenTtlSeconds(),
        request.usePlatformTokenTtls());
    updateIcon(app, request);
    audit.recordAppChange("APP_UPDATED", owner, id);
    return response(app, true);
  }

  private void updateIcon(App app, AppDtos.UpdateAppRequest request) {
    String iconUrl = request.iconUrl();
    String iconDataUrl = request.iconDataUrl();
    if (iconUrl != null || iconDataUrl != null) {
      String normalizedUrl = iconUrl == null ? "" : iconUrl.trim();
      String normalizedDataUrl = iconDataUrl == null ? "" : iconDataUrl.trim();
      boolean hasUrl = !normalizedUrl.isEmpty();
      boolean hasData = !normalizedDataUrl.isEmpty();
      if (hasUrl && hasData) {
        throw invalidIcon();
      }
      if (!hasUrl && !hasData) {
        app.clearIcon();
      } else if (hasUrl) {
        app.setIconUrl(validateIconUrl(normalizedUrl));
      } else {
        DecodedIcon decoded = decodeIconDataUrl(normalizedDataUrl);
        app.setIconData(decoded.bytes(), decoded.contentType());
      }
    }
    app.updateIconCrop(
        request.iconPositionX(), request.iconPositionY(), request.iconZoomPercent());
  }

  private String validateIconUrl(String value) {
    if (value.length() > 2048) throw invalidIcon();
    try {
      URI uri = URI.create(value);
      String scheme = uri.getScheme();
      String host = uri.getHost();
      boolean secure = "https".equalsIgnoreCase(scheme);
      String normalizedHost = host == null ? "" : host.toLowerCase(Locale.ROOT);
      boolean localDevelopment =
          "http".equalsIgnoreCase(scheme)
              && List.of("localhost", "127.0.0.1", "::1", "[::1]").contains(normalizedHost);
      if ((!secure && !localDevelopment)
          || host == null
          || uri.getRawUserInfo() != null
          || uri.getRawFragment() != null) {
        throw invalidIcon();
      }
      return value;
    } catch (IllegalArgumentException error) {
      throw invalidIcon();
    }
  }

  private DecodedIcon decodeIconDataUrl(String value) {
    if (value.length() > MAX_ICON_DATA_URL_LENGTH) throw invalidIcon();
    int comma = value.indexOf(',');
    if (comma < 0) throw invalidIcon();
    String header = value.substring(0, comma);
    String contentType =
        switch (header) {
          case "data:image/png;base64" -> "image/png";
          case "data:image/jpeg;base64" -> "image/jpeg";
          case "data:image/webp;base64" -> "image/webp";
          default -> throw invalidIcon();
        };
    byte[] bytes;
    try {
      bytes = Base64.getDecoder().decode(value.substring(comma + 1));
    } catch (IllegalArgumentException error) {
      throw invalidIcon();
    }
    if (bytes.length == 0 || bytes.length > MAX_ICON_BYTES || !hasImageSignature(bytes, contentType)) {
      throw invalidIcon();
    }
    return new DecodedIcon(bytes, contentType);
  }

  private boolean hasImageSignature(byte[] bytes, String contentType) {
    return switch (contentType) {
      case "image/png" ->
          bytes.length >= 8
              && (bytes[0] & 0xff) == 0x89
              && bytes[1] == 0x50
              && bytes[2] == 0x4e
              && bytes[3] == 0x47
              && bytes[4] == 0x0d
              && bytes[5] == 0x0a
              && bytes[6] == 0x1a
              && bytes[7] == 0x0a;
      case "image/jpeg" ->
          bytes.length >= 3
              && (bytes[0] & 0xff) == 0xff
              && (bytes[1] & 0xff) == 0xd8
              && (bytes[2] & 0xff) == 0xff;
      case "image/webp" ->
          bytes.length >= 12
              && "RIFF".equals(new String(bytes, 0, 4, StandardCharsets.US_ASCII))
              && "WEBP".equals(new String(bytes, 8, 4, StandardCharsets.US_ASCII));
      default -> false;
    };
  }

  private ApiException invalidIcon() {
    return new ApiException(
        ErrorCode.VALIDATION_FAILED,
        "Use an HTTPS image URL or a PNG, JPEG, or WebP image smaller than 375 KB.");
  }

  private record DecodedIcon(byte[] bytes, String contentType) {}

  @Transactional
  public AppDtos.RotatedSecretResponse rotate(UUID owner, UUID id) {
    App app =
        apps.findByIdAndOwnerAccountId(id, owner)
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    String secret = generator.generateSecretKey();
    app.rotateSecret(hasher.hash(secret), hint(secret));
    audit.recordAppChange("SECRET_KEY_ROTATED", owner, id);
    return new AppDtos.RotatedSecretResponse(id, secret, app.getSecretKeyHint());
  }

  @Transactional
  public AppDtos.AppUserView updateUser(
      UUID owner, UUID appId, UUID userId, AppDtos.UpdateAppUserRequest request) {
    apps.findByIdAndOwnerAccountId(appId, owner)
        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    AppUser user =
        users
            .findByAppIdAndId(appId, userId)
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    user.updateBySa(
        request.name(),
        request.status(),
        request.emailVerified(),
        request.password() == null ? null : passwords.hash(request.password()));
    audit.recordAppChange("APP_USER_UPDATED", owner, appId);
    return new AppDtos.AppUserView(
        user.getId(),
        user.getAppId(),
        user.getName(),
        user.getEmail(),
        user.isEmailVerified(),
        user.getStatus(),
        user.getLastLoginAt(),
        user.getCreatedAt());
  }

  @Transactional
  public void deleteUser(UUID owner, UUID appId, UUID userId) {
    apps.findByIdAndOwnerAccountId(appId, owner)
        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    AppUser user =
        users
            .findByAppIdAndId(appId, userId)
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    sessions.revokeAllForAppUser(userId);
    users.delete(user);
    audit.recordAppChange("APP_USER_DELETED", owner, appId);
  }

  @Transactional(readOnly = true)
  public App findByPublishableKey(String key) {
    return apps.findByPublishableKey(key)
        .orElseThrow(() -> new ApiException(ErrorCode.INVALID_KEY));
  }

  private AppDtos.AppResponse response(App app, boolean includeIconData) {
    return new AppDtos.AppResponse(
        app.getId(),
        app.getName(),
        app.getPublishableKey(),
        app.getAllowedOrigins(),
        app.getVerifyEmailUrl(),
        app.isRequireEmailVerification(),
        app.isMfaRequired(),
        app.getStatus(),
        app.getCreatedAt(),
        app.getSecretKeyHint(),
        roles.findDefault(app.getId()),
        app.getAccessTokenTtlSeconds(),
        app.getRefreshTokenTtlSeconds(),
        app.getIconUrl(),
        includeIconData ? app.getIconDataUrl() : null,
        app.getIconPositionX(),
        app.getIconPositionY(),
        app.getIconZoomPercent());
  }

  private AppDtos.AppUserView userView(AppUser user) {
    return new AppDtos.AppUserView(
        user.getId(),
        user.getAppId(),
        user.getName(),
        user.getEmail(),
        user.isEmailVerified(),
        user.getStatus(),
        user.getLastLoginAt(),
        user.getCreatedAt());
  }

  private List<String> origins(List<String> values) {
    List<String> list = values == null ? List.of() : List.copyOf(values);
    if (list.size() > maxOrigins
        || list.stream().anyMatch(v -> !v.matches("https://[^/]+|http://localhost(:[0-9]+)?")))
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED, "Origins must be exact https://host or localhost origins");
    return list;
  }

  private String hint(String secret) {
    return secret.substring(Math.max(0, secret.length() - 4));
  }

  private PageRequest pageRequest(int page, int size) {
    return PageRequest.of(Math.max(page, 0), size, Sort.by(Sort.Direction.DESC, "createdAt", "id"));
  }
}
