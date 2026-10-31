package com.authplatform.app.service;

import com.authplatform.app.dto.AppDtos;
import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.audit.AuditService;
import com.authplatform.auth.service.OneTimeTokenService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.dto.PageResult;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.role.service.RoleService;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AppUserRepository;
import com.authplatform.user.service.AppUserDirectory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Console-owner operations on an application's end users: paged listing and invitations. */
@Service
public class EndUserService {
  public static final int MAX_INVITEES_PER_REQUEST = 50;
  private static final Pattern EMAIL = Pattern.compile("^[^\\s@<>\"',;]+@[^\\s@<>\"',;]+\\.[^\\s@<>\"',;]+$");
  private static final Duration INVITE_WINDOW = Duration.ofHours(1);

  private final AppRepository apps;
  private final AppUserRepository users;
  private final AppUserDirectory directory;
  private final PasswordHasher passwords;
  private final OneTimeTokenService tokens;
  private final RoleService roles;
  private final EmailSender email;
  private final EmailTemplateService templates;
  private final AuditService audit;
  private final StringRedisTemplate redis;
  private final int invitesPerHour;

  public EndUserService(
      AppRepository apps,
      AppUserRepository users,
      AppUserDirectory directory,
      PasswordHasher passwords,
      OneTimeTokenService tokens,
      RoleService roles,
      EmailSender email,
      EmailTemplateService templates,
      AuditService audit,
      StringRedisTemplate redis,
      @Value("${authplatform.limits.invites-per-hour:200}") int invitesPerHour) {
    this.apps = apps;
    this.users = users;
    this.directory = directory;
    this.passwords = passwords;
    this.tokens = tokens;
    this.roles = roles;
    this.email = email;
    this.templates = templates;
    this.audit = audit;
    this.redis = redis;
    this.invitesPerHour = invitesPerHour;
  }

  @Transactional(readOnly = true)
  public PageResult<AppDtos.AppUserView> list(
      UUID owner,
      UUID appId,
      String query,
      String status,
      String sort,
      String direction,
      int page,
      int size) {
    ownedApp(owner, appId);
    return PageResult.of(
        directory.search(appId, query, status, sort, direction, page, size).map(EndUserService::view));
  }

  @Transactional
  public AppDtos.InviteUsersResponse invite(
      UUID owner, UUID appId, AppDtos.InviteUsersRequest request) {
    App app = ownedApp(owner, appId);
    List<AppDtos.InviteeRequest> invitees = request.users();
    if (invitees.size() > MAX_INVITEES_PER_REQUEST) {
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED,
          "Invite at most " + MAX_INVITEES_PER_REQUEST + " users per request");
    }
    // Fail before creating anything if verification links cannot be built for this application.
    templates.appVerificationLink(app, "check");

    Map<String, AppDtos.InviteResult> results = new LinkedHashMap<>();
    Map<String, String> toInvite = new LinkedHashMap<>();
    for (AppDtos.InviteeRequest invitee : invitees) {
      String address = normalize(invitee.email());
      if (!isValid(address)) {
        results.put(
            "invalid:" + results.size(),
            new AppDtos.InviteResult(
                clip(invitee.email()), "INVALID", "This is not a valid email address"));
      } else if (results.containsKey(address)) {
        results.put(
            "duplicate:" + results.size(),
            new AppDtos.InviteResult(address, "DUPLICATE", "Listed more than once"));
      } else {
        results.put(address, null);
        toInvite.put(address, displayName(invitee.name(), address));
      }
    }

    Set<String> existing = existingEmails(appId, toInvite.keySet());
    toInvite.keySet().removeIf(address -> {
      if (!existing.contains(address)) return false;
      results.put(
          address,
          new AppDtos.InviteResult(address, "ALREADY_EXISTS", "A user with this email already exists"));
      return true;
    });

    reserveQuota(owner, toInvite.size());
    List<Invitation> created = createUsers(app, toInvite);
    for (Invitation invitation : created) {
      results.put(
          invitation.user().getEmail(),
          new AppDtos.InviteResult(
              invitation.user().getEmail(), "INVITED", "Invitation sent"));
    }
    sendAfterCommit(app, created);
    if (!created.isEmpty()) {
      audit.recordAppChange(
          "APP_USERS_INVITED",
          owner,
          appId,
          Map.of("requested", invitees.size(), "invited", created.size()));
    }
    List<AppDtos.InviteResult> ordered = new ArrayList<>(results.values());
    return new AppDtos.InviteUsersResponse(
        invitees.size(), created.size(), invitees.size() - created.size(), ordered);
  }

  @Transactional
  public AppDtos.AppUserView resendInvitation(UUID owner, UUID appId, UUID userId) {
    App app = ownedApp(owner, appId);
    AppUser user =
        users.findByAppIdAndId(appId, userId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    if (!user.isInvited()) {
      throw new ApiException(
          ErrorCode.VALIDATION_FAILED, "Only users who have not signed in yet can be re-invited");
    }
    reserveQuota(owner, 1);
    String password = TemporaryPassword.generate();
    user.reinvite(passwords.hash(password));
    String token = tokens.issueAppUser(user.getId(), com.authplatform.auth.entity.EmailTokenType.VERIFY_EMAIL).rawToken();
    runAfterCommit(
        () ->
            email.send(
                templates.invitation(
                    app,
                    user.getEmail(),
                    user.getName(),
                    password,
                    templates.appVerificationLink(app, token))));
    audit.recordAppChange("APP_USER_REINVITED", owner, appId);
    return view(user);
  }

  private List<Invitation> createUsers(App app, Map<String, String> toInvite) {
    if (toInvite.isEmpty()) return List.of();
    // Argon2 is deliberately slow, so hash the temporary passwords in parallel before touching the database.
    List<Map.Entry<String, String>> entries = List.copyOf(toInvite.entrySet());
    List<String> clearPasswords = entries.stream().map(entry -> TemporaryPassword.generate()).toList();
    List<String> hashes =
        java.util.stream.IntStream.range(0, entries.size())
            .parallel()
            .mapToObj(index -> passwords.hash(clearPasswords.get(index)))
            .toList();
    List<AppUser> newUsers = new ArrayList<>(entries.size());
    for (int i = 0; i < entries.size(); i++) {
      newUsers.add(
          AppUser.invite(app.getId(), entries.get(i).getKey(), hashes.get(i), entries.get(i).getValue()));
    }
    try {
      users.saveAllAndFlush(newUsers);
    } catch (org.springframework.dao.DataIntegrityViolationException ex) {
      throw new ApiException(ErrorCode.EMAIL_TAKEN, "Some users were created by someone else while inviting. Try again.");
    }
    List<UUID> ids = newUsers.stream().map(AppUser::getId).toList();
    roles.assignDefaultRole(app.getId(), ids);
    Map<UUID, String> verification = tokens.issueVerificationForNewAppUsers(ids);
    List<Invitation> invitations = new ArrayList<>(newUsers.size());
    for (int i = 0; i < newUsers.size(); i++) {
      AppUser user = newUsers.get(i);
      invitations.add(new Invitation(user, clearPasswords.get(i), verification.get(user.getId())));
    }
    return invitations;
  }

  private void sendAfterCommit(App app, List<Invitation> invitations) {
    runAfterCommit(
        () -> {
          for (Invitation invitation : invitations) {
            email.send(
                templates.invitation(
                    app,
                    invitation.user().getEmail(),
                    invitation.user().getName(),
                    invitation.password(),
                    templates.appVerificationLink(app, invitation.token())));
          }
        });
  }

  // Emails carry credentials, so they must not go out for a transaction that later rolls back.
  private static void runAfterCommit(Runnable action) {
    if (!TransactionSynchronizationManager.isSynchronizationActive()) {
      action.run();
      return;
    }
    TransactionSynchronizationManager.registerSynchronization(
        new TransactionSynchronization() {
          @Override
          public void afterCommit() {
            action.run();
          }
        });
  }

  // Stops the platform being used as an open mail relay: invitations are capped per owner per hour.
  private void reserveQuota(UUID owner, int count) {
    if (count == 0) return;
    try {
      String key = "authplatform:invites:" + owner;
      Long total = redis.opsForValue().increment(key, count);
      if (total != null && total == count) redis.expire(key, INVITE_WINDOW);
      if (total != null && total > invitesPerHour) {
        redis.opsForValue().decrement(key, count);
        throw new ApiException(
            ErrorCode.RATE_LIMITED,
            "Invitation limit reached. You can invite up to " + invitesPerHour + " users per hour.");
      }
    } catch (ApiException ex) {
      throw ex;
    } catch (RuntimeException ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }

  private Set<String> existingEmails(UUID appId, java.util.Collection<String> addresses) {
    if (addresses.isEmpty()) return Set.of();
    return users.findAllByAppIdAndLowerEmailIn(appId, addresses).stream()
        .map(user -> user.getEmail().toLowerCase(Locale.ROOT))
        .collect(java.util.stream.Collectors.toSet());
  }

  private App ownedApp(UUID owner, UUID appId) {
    return apps.findByIdAndOwnerAccountId(appId, owner)
        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
  }

  static String normalize(String email) {
    return email == null ? "" : email.strip().toLowerCase(Locale.ROOT);
  }

  static boolean isValid(String address) {
    return address.length() <= 320 && EMAIL.matcher(address).matches();
  }

  static String displayName(String name, String address) {
    String cleaned = name == null ? "" : name.replaceAll("\\p{Cntrl}", " ").strip();
    if (!cleaned.isEmpty()) return cleaned.length() > 120 ? cleaned.substring(0, 120) : cleaned;
    String local = address.substring(0, address.indexOf('@')).replaceAll("[._+\\-]+", " ").strip();
    if (local.isEmpty()) return address.substring(0, Math.min(address.length(), 120));
    StringBuilder words = new StringBuilder();
    for (String word : local.split("\\s+")) {
      if (words.length() > 0) words.append(' ');
      words.append(Character.toUpperCase(word.charAt(0))).append(word.substring(1));
    }
    return words.length() > 120 ? words.substring(0, 120) : words.toString();
  }

  private static String clip(String value) {
    if (value == null) return "";
    String text = value.replaceAll("\\p{Cntrl}", " ").strip();
    return text.length() > 120 ? text.substring(0, 120) + "…" : text;
  }

  private static AppDtos.AppUserView view(AppUser user) {
    return new AppDtos.AppUserView(
        user.getId(),
        user.getAppId(),
        user.getName(),
        user.getEmail(),
        user.isEmailVerified(),
        user.getStatus(),
        user.getLastLoginAt(),
        user.getCreatedAt(),
        user.isInvited());
  }

  private record Invitation(AppUser user, String password, String token) {}
}
