package com.authplatform.sa.service;

import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.audit.AuditLog;
import com.authplatform.audit.AuditLogRepository;
import com.authplatform.audit.AuditService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.app.service.TokenLifetimePolicy;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.crypto.SecureTokenGenerator;
import com.authplatform.common.crypto.TokenHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.common.security.RedirectUrlValidator;
import com.authplatform.sa.dto.SaDtos;
import com.authplatform.user.entity.Account;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.entity.PlatformRole;
import com.authplatform.user.repository.AccountRepository;
import com.authplatform.user.repository.AppUserRepository;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SaService {
  private final AccountRepository accounts;
  private final AppRepository apps;
  private final AppUserRepository users;
  private final AuditLogRepository auditLogs;
  private final PasswordHasher passwords;
  private final SecureTokenGenerator generator;
  private final TokenHasher hasher;
  private final SessionService sessions;
  private final AuditService audit;

  public SaService(
      AccountRepository accounts,
      AppRepository apps,
      AppUserRepository users,
      AuditLogRepository auditLogs,
      PasswordHasher passwords,
      SecureTokenGenerator generator,
      TokenHasher hasher,
      SessionService sessions,
      AuditService audit) {
    this.accounts = accounts;
    this.apps = apps;
    this.users = users;
    this.auditLogs = auditLogs;
    this.passwords = passwords;
    this.generator = generator;
    this.hasher = hasher;
    this.sessions = sessions;
    this.audit = audit;
  }

  @Transactional(readOnly = true)
  public SaDtos.AnalyticsOverview analytics(UUID actorId, String ip) {
    List<SaDtos.AppUserCount> usersByApp =
        apps.findAllByOrderByCreatedAtDesc().stream()
            .map(
                app ->
                    new SaDtos.AppUserCount(
                        app.getId(), app.getName(), users.countByAppId(app.getId())))
            .toList();
    audit.recordSa("SA_VIEW_ANALYTICS", actorId, null, ip, null);
    return new SaDtos.AnalyticsOverview(
        accounts.count(),
        accounts.countByStatus("ACTIVE"),
        accounts.countByEmailVerifiedTrue(),
        apps.count(),
        apps.countByStatus("ACTIVE"),
        users.count(),
        users.countByStatus("ACTIVE"),
        usersByApp);
  }

  @Transactional(readOnly = true)
  public SaDtos.AccountView currentAccount(UUID actorId) {
    return accounts
        .findById(actorId)
        .map(this::accountView)
        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
  }

  @Transactional(readOnly = true)
  public SaDtos.PageResponse<SaDtos.AccountView> accounts(
      int page, int size, UUID actorId, String ip) {
    Page<Account> result = accounts.findAll(pageRequest(page, size));
    audit.recordSa("SA_VIEW_ACCOUNTS", actorId, null, ip, Map.of("page", page, "size", size));
    return pageResponse(result.map(this::accountView));
  }

  @Transactional(readOnly = true)
  public SaDtos.AccountDetails account(UUID id, UUID actorId, String ip) {
    Account account = findAccount(id);
    audit.recordSa("SA_VIEW_ACCOUNT", actorId, null, ip, Map.of("targetAccountId", id.toString()));
    return new SaDtos.AccountDetails(
        accountView(account),
        apps.findAllByOwnerAccountIdOrderByCreatedAtDesc(id).stream().map(this::appView).toList());
  }

  @Transactional
  public SaDtos.AccountView createSa(SaDtos.CreateSaRequest request, UUID actorId, String ip) {
    String email = normalize(request.email());
    if (accounts.existsByEmailIgnoreCase(email)) throw new ApiException(ErrorCode.EMAIL_TAKEN);
    validatePassword(request.password(), email);
    Account account;
    try {
      account =
          accounts.saveAndFlush(
              Account.registerSa(email, passwords.hash(request.password()), request.name().trim()));
    } catch (org.springframework.dao.DataIntegrityViolationException ex) {
      throw new ApiException(ErrorCode.EMAIL_TAKEN);
    }
    audit.recordSa(
        "SA_CREATED",
        actorId,
        null,
        ip,
        Map.of("targetAccountId", account.getId().toString(), "email", account.getEmail()));
    return accountView(account);
  }

  @Transactional
  public SaDtos.AccountView updateAccount(
      UUID id, SaDtos.UpdateAccountRequest request, UUID actorId, String ip) {
    Account account = findAccount(id);
    PlatformRole oldRole = account.getPlatformRole();
    PlatformRole newRole = request.platformRole() == null ? oldRole : request.platformRole();
    String newStatus = request.status() == null ? account.getStatus() : request.status();
    validateStatus(newStatus);
    if (oldRole == PlatformRole.SA
        && newRole != PlatformRole.SA
        && accounts.countByPlatformRole(PlatformRole.SA) <= 1)
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "The last SA account cannot be demoted");
    if (request.password() != null) validatePassword(request.password(), account.getEmail());
    account.updateBySa(
        request.name(),
        newStatus,
        newRole,
        request.password() == null ? null : passwords.hash(request.password()));
    if (newRole == PlatformRole.SA) account.markEmailVerified();
    if (!"ACTIVE".equals(newStatus) || oldRole != newRole || request.password() != null)
      sessions.revokeAllForAccount(id);
    audit.recordSa(
        "SA_ACCOUNT_UPDATED",
        actorId,
        null,
        ip,
        Map.of(
            "targetAccountId", id.toString(),
            "oldRole", oldRole.name(),
            "newRole", newRole.name(),
            "newStatus", newStatus));
    return accountView(account);
  }

  @Transactional(readOnly = true)
  public SaDtos.PageResponse<SaDtos.AppView> apps(int page, int size, UUID actorId, String ip) {
    Page<App> result = apps.findAll(pageRequest(page, size));
    audit.recordSa("SA_VIEW_APPS", actorId, null, ip, Map.of("page", page, "size", size));
    return pageResponse(result.map(this::appView));
  }

  @Transactional(readOnly = true)
  public SaDtos.AppView app(UUID id, UUID actorId, String ip) {
    App app = findApp(id);
    audit.recordSa("SA_VIEW_APP", actorId, id, ip, Map.of("targetAppId", id.toString()));
    return appView(app);
  }

  @Transactional
  public SaDtos.AppView updateApp(
      UUID id, SaDtos.UpdateAppRequest request, UUID actorId, String ip) {
    App app = findApp(id);
    TokenLifetimePolicy.validateUpdate(
        request.accessTokenTtlSeconds(),
        request.refreshTokenTtlSeconds(),
        request.usePlatformTokenTtls());
    if (request.allowedOrigins() != null) validateOrigins(request.allowedOrigins());
    String verifyEmailUrl = RedirectUrlValidator.validate(request.verifyEmailUrl());
    String resetPasswordUrl = RedirectUrlValidator.validate(request.resetPasswordUrl());
    String status = request.status() == null ? app.getStatus() : request.status();
    if (!List.of("ACTIVE", "SUSPENDED").contains(status))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "App status must be ACTIVE or SUSPENDED");
    app.update(
        request.name(),
        request.allowedOrigins(),
        verifyEmailUrl,
        resetPasswordUrl,
        request.requireEmailVerification(),
        status,
        request.mfaRequired(),
        request.accessTokenTtlSeconds(),
        request.refreshTokenTtlSeconds(),
        request.usePlatformTokenTtls());
    audit.recordSa("SA_APP_UPDATED", actorId, id, ip, Map.of("targetAppId", id.toString()));
    return appView(app);
  }

  @Transactional
  public SaDtos.RotatedSecretResponse rotateSecret(UUID id, UUID actorId, String ip) {
    App app = findApp(id);
    String secret = generator.generateSecretKey();
    app.rotateSecret(hasher.hash(secret), secret.substring(Math.max(0, secret.length() - 4)));
    audit.recordSa("SA_APP_SECRET_ROTATED", actorId, id, ip, Map.of("targetAppId", id.toString()));
    return new SaDtos.RotatedSecretResponse(id, secret, app.getSecretKeyHint());
  }

  @Transactional(readOnly = true)
  public SaDtos.PageResponse<SaDtos.AppUserView> users(
      int page, int size, UUID actorId, String ip) {
    Page<AppUser> result = users.findAll(pageRequest(page, size));
    audit.recordSa("SA_VIEW_USERS", actorId, null, ip, Map.of("page", page, "size", size));
    return pageResponse(result.map(this::userView));
  }

  @Transactional(readOnly = true)
  public SaDtos.PageResponse<SaDtos.AppUserView> appUsers(
      UUID appId, int page, int size, UUID actorId, String ip) {
    findApp(appId);
    List<AppUser> all = users.findAllByAppIdOrderByCreatedAtDesc(appId);
    int safePage = Math.max(page, 0);
    int safeSize = Math.min(Math.max(size, 1), 100);
    int from = Math.min(safePage * safeSize, all.size());
    int to = Math.min(from + safeSize, all.size());
    audit.recordSa("SA_VIEW_APP_USERS", actorId, appId, ip, Map.of("appId", appId.toString()));
    return new SaDtos.PageResponse<>(
        all.subList(from, to).stream().map(this::userView).toList(),
        safePage,
        safeSize,
        all.size(),
        (int) Math.ceil(all.size() / (double) safeSize));
  }

  @Transactional
  public SaDtos.AppUserView updateUser(
      UUID appId, UUID userId, SaDtos.UpdateAppUserRequest request, UUID actorId, String ip) {
    findApp(appId);
    AppUser user =
        users
            .findByAppIdAndId(appId, userId)
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    String status = request.status() == null ? user.getStatus() : request.status();
    validateUserStatus(status);
    if (request.password() != null) validatePassword(request.password(), user.getEmail());
    user.updateBySa(
        request.name(),
        status,
        request.emailVerified(),
        request.password() == null ? null : passwords.hash(request.password()));
    if (!"ACTIVE".equals(status) || request.password() != null)
      sessions.revokeAllForAppUser(userId);
    audit.recordSa(
        "SA_APP_USER_UPDATED",
        actorId,
        appId,
        ip,
        Map.of("targetAppUserId", userId.toString(), "targetAppId", appId.toString()));
    return userView(user);
  }

  @Transactional
  public void deleteUser(UUID appId, UUID userId, UUID actorId, String ip) {
    findApp(appId);
    AppUser user =
        users
            .findByAppIdAndId(appId, userId)
            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    sessions.revokeAllForAppUser(userId);
    users.delete(user);
    audit.recordSa(
        "SA_APP_USER_DELETED",
        actorId,
        appId,
        ip,
        Map.of("targetAppUserId", userId.toString(), "targetAppId", appId.toString()));
  }

  @Transactional(readOnly = true)
  public SaDtos.PageResponse<SaDtos.AuditLogView> auditLogs(
      int page, int size, UUID actorId, String ip) {
    Page<AuditLog> result = auditLogs.findAllByOrderByCreatedAtDesc(pageRequest(page, size));
    audit.recordSa("SA_VIEW_AUDIT_LOGS", actorId, null, ip, Map.of("page", page, "size", size));
    return pageResponse(result.map(this::auditView));
  }

  private Account findAccount(UUID id) {
    return accounts.findById(id).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
  }

  private App findApp(UUID id) {
    return apps.findById(id).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
  }

  private SaDtos.AccountView accountView(Account account) {
    return new SaDtos.AccountView(
        account.getId(),
        account.getName(),
        account.getEmail(),
        account.isEmailVerified(),
        account.getPlatformRole(),
        account.getStatus(),
        account.getCreatedAt(),
        apps.countByOwnerAccountId(account.getId()));
  }

  private SaDtos.AppView appView(App app) {
    String ownerEmail =
        accounts.findById(app.getOwnerAccountId()).map(Account::getEmail).orElse(null);
    return new SaDtos.AppView(
        app.getId(),
        app.getName(),
        app.getPublishableKey(),
        app.getOwnerAccountId(),
        ownerEmail,
        app.getAllowedOrigins(),
        app.isRequireEmailVerification(),
        app.isMfaRequired(),
        app.getStatus(),
        app.getCreatedAt(),
        app.getSecretKeyHint(),
        users.countByAppId(app.getId()),
        app.getAccessTokenTtlSeconds(),
        app.getRefreshTokenTtlSeconds());
  }

  private SaDtos.AppUserView userView(AppUser user) {
    return new SaDtos.AppUserView(
        user.getId(),
        user.getAppId(),
        user.getName(),
        user.getEmail(),
        user.isEmailVerified(),
        user.getStatus(),
        user.getLastLoginAt(),
        user.getCreatedAt());
  }

  private SaDtos.AuditLogView auditView(AuditLog log) {
    return new SaDtos.AuditLogView(
        log.getId(),
        log.getAppId(),
        log.getActorAccountId(),
        log.getActorAppUserId(),
        log.getActorType(),
        log.getAction(),
        log.getIpAddress(),
        log.getRequestId(),
        log.getCreatedAt(),
        log.getMetadata());
  }

  private static <T> SaDtos.PageResponse<T> pageResponse(Page<T> page) {
    return new SaDtos.PageResponse<>(
        page.getContent(),
        page.getNumber(),
        page.getSize(),
        page.getTotalElements(),
        page.getTotalPages());
  }

  private static PageRequest pageRequest(int page, int size) {
    return PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100));
  }

  private static void validateStatus(String status) {
    if (!List.of("ACTIVE", "SUSPENDED", "BLOCKED").contains(status))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "Account status is invalid");
  }

  private static void validateUserStatus(String status) {
    if (!List.of("ACTIVE", "SUSPENDED", "BLOCKED").contains(status))
      throw new ApiException(ErrorCode.VALIDATION_FAILED, "User status is invalid");
  }

  private static void validateOrigins(List<String> values) {
    if (values.size() > 20
        || values.stream()
            .anyMatch(value -> !value.matches("https://[^/]+|http://localhost(:[0-9]+)?")))
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED, "Origins must be exact https://host or localhost origins");
  }

  private static String normalize(String email) {
    return email.trim().toLowerCase(Locale.ROOT);
  }

  private static void validatePassword(String password, String email) {
    String local = email.substring(0, email.indexOf('@'));
    if (password.length() < 10
        || password.length() > 128
        || !password.matches(".*[A-Za-z].*")
        || !password.matches(".*\\d.*")
        || password.toLowerCase(Locale.ROOT).contains(local))
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED,
          "Password must be 10-128 characters with a letter and digit and must not contain the email local part");
  }
}
