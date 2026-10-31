package com.authplatform.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authplatform.app.dto.AppDtos;
import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.audit.AuditService;
import com.authplatform.auth.service.OneTimeTokenService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailMessage;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.role.service.RoleService;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AppUserRepository;
import com.authplatform.user.service.AppUserDirectory;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

class EndUserServiceTest {
  private final UUID owner = UUID.randomUUID();
  private final UUID appId = UUID.randomUUID();
  private AppRepository apps;
  private AppUserRepository users;
  private OneTimeTokenService tokens;
  private RoleService roles;
  private EmailSender email;
  private AuditService audit;
  private ValueOperations<String, String> counters;
  private EndUserService service;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    apps = mock(AppRepository.class);
    users = mock(AppUserRepository.class);
    tokens = mock(OneTimeTokenService.class);
    roles = mock(RoleService.class);
    email = mock(EmailSender.class);
    audit = mock(AuditService.class);
    PasswordHasher passwords = mock(PasswordHasher.class);
    when(passwords.hash(any())).thenAnswer(call -> "hash:" + call.getArgument(0));
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    counters = mock(ValueOperations.class);
    when(redis.opsForValue()).thenReturn(counters);
    when(counters.increment(any(String.class), anyLong()))
        .thenAnswer(call -> call.getArgument(1, Long.class));

    App app = mock(App.class);
    when(app.getId()).thenReturn(appId);
    when(app.getName()).thenReturn("Acme");
    when(app.getVerifyEmailUrl()).thenReturn("https://acme.example/verify-email");
    when(apps.findByIdAndOwnerAccountId(appId, owner)).thenReturn(Optional.of(app));
    when(users.findAllByAppIdAndLowerEmailIn(eq(appId), anyCollection())).thenReturn(List.of());
    when(tokens.issueVerificationForNewAppUsers(anyCollection()))
        .thenAnswer(
            call -> {
              Map<UUID, String> raw = new java.util.LinkedHashMap<>();
              for (UUID id : call.<java.util.Collection<UUID>>getArgument(0)) raw.put(id, "tok-" + id);
              return raw;
            });
    service =
        new EndUserService(
            apps,
            users,
            new AppUserDirectory(users),
            passwords,
            tokens,
            roles,
            email,
            new EmailTemplateService(""),
            audit,
            redis,
            100);
  }

  private static AppDtos.InviteUsersRequest request(String... emails) {
    return new AppDtos.InviteUsersRequest(
        java.util.Arrays.stream(emails).map(e -> new AppDtos.InviteeRequest(e, null)).toList());
  }

  @Test
  void invitesNewUsersAndSendsOneEmailEachWithTemporaryPasswordAndLink() {
    var response = service.invite(owner, appId, request("Ada.Lovelace@Example.com", "grace@example.com"));

    assertThat(response.invited()).isEqualTo(2);
    assertThat(response.results()).extracting(AppDtos.InviteResult::outcome).containsOnly("INVITED");
    ArgumentCaptor<List<AppUser>> saved = ArgumentCaptor.forClass(List.class);
    verify(users).saveAllAndFlush(saved.capture());
    assertThat(saved.getValue()).allSatisfy(user -> assertThat(user.isInvited()).isTrue());
    assertThat(saved.getValue().get(0).getEmail()).isEqualTo("ada.lovelace@example.com");
    assertThat(saved.getValue().get(0).getName()).isEqualTo("Ada Lovelace");
    assertThat(saved.getValue().get(0).getPasswordHash()).startsWith("hash:");
    verify(roles).assignDefaultRole(eq(appId), anyCollection());

    ArgumentCaptor<EmailMessage> mails = ArgumentCaptor.forClass(EmailMessage.class);
    verify(email, times(2)).send(mails.capture());
    String body = mails.getAllValues().get(0).textBody();
    assertThat(body).contains("Temporary password:", "https://acme.example/verify-email?token=tok-");
    assertThat(mails.getAllValues().get(0).to()).isEqualTo("ada.lovelace@example.com");
    verify(audit).recordAppChange(eq("APP_USERS_INVITED"), eq(owner), eq(appId), any());
  }

  @Test
  void reportsInvalidDuplicateAndExistingAddressesWithoutFailingTheBatch() {
    AppUser existing = AppUser.register(appId, "taken@example.com", "h", "Taken");
    when(users.findAllByAppIdAndLowerEmailIn(eq(appId), anyCollection())).thenReturn(List.of(existing));

    var response =
        service.invite(
            owner,
            appId,
            request("new@example.com", "NEW@example.com", "nope", "a@b.c\r\nBcc: x@y.z", "taken@example.com"));

    assertThat(response.requested()).isEqualTo(5);
    assertThat(response.invited()).isEqualTo(1);
    assertThat(response.results())
        .extracting(AppDtos.InviteResult::outcome)
        .containsExactly("INVITED", "DUPLICATE", "INVALID", "INVALID", "ALREADY_EXISTS");
    verify(email, times(1)).send(any(EmailMessage.class));
  }

  @Test
  void refusesWhenTheHourlyQuotaIsExceededAndCreatesNothing() {
    when(counters.increment(any(String.class), anyLong())).thenReturn(101L);

    assertThatThrownBy(() -> service.invite(owner, appId, request("a@example.com")))
        .isInstanceOfSatisfying(
            ApiException.class, ex -> assertThat(ex.code()).isEqualTo(ErrorCode.RATE_LIMITED));
    verify(users, never()).saveAllAndFlush(any());
    verify(email, never()).send(any(EmailMessage.class));
    verify(counters).decrement(any(String.class), eq(1L));
  }

  @Test
  void failsClosedWhenTheQuotaStoreIsUnavailable() {
    when(counters.increment(any(String.class), anyLong())).thenThrow(new IllegalStateException("redis down"));

    assertThatThrownBy(() -> service.invite(owner, appId, request("a@example.com")))
        .isInstanceOfSatisfying(
            ApiException.class,
            ex -> assertThat(ex.code()).isEqualTo(ErrorCode.RATE_LIMIT_UNAVAILABLE));
    verify(users, never()).saveAllAndFlush(any());
  }

  @Test
  void rejectsMoreThanTheMaximumBatchSize() {
    String[] many = new String[EndUserService.MAX_INVITEES_PER_REQUEST + 1];
    for (int i = 0; i < many.length; i++) many[i] = "u" + i + "@example.com";

    assertThatThrownBy(() -> service.invite(owner, appId, request(many))).isInstanceOf(ApiException.class);
  }

  @Test
  void onlyTheOwnerCanInviteOrResend() {
    UUID stranger = UUID.randomUUID();

    assertThatThrownBy(() -> service.invite(stranger, appId, request("a@example.com")))
        .isInstanceOfSatisfying(
            ApiException.class, ex -> assertThat(ex.code()).isEqualTo(ErrorCode.NOT_FOUND));
    assertThatThrownBy(() -> service.resendInvitation(stranger, appId, UUID.randomUUID()))
        .isInstanceOf(ApiException.class);
  }

  @Test
  void usersWhoAlreadySignedInCannotBeReinvited() {
    AppUser active = AppUser.invite(appId, "a@example.com", "h", "A");
    active.markLogin(java.time.Instant.now());
    when(users.findByAppIdAndId(eq(appId), any())).thenReturn(Optional.of(active));

    assertThatThrownBy(() -> service.resendInvitation(owner, appId, UUID.randomUUID()))
        .isInstanceOfSatisfying(
            ApiException.class, ex -> assertThat(ex.code()).isEqualTo(ErrorCode.VALIDATION_FAILED));
    verify(email, never()).send(any(EmailMessage.class));
  }

  @Test
  void derivesReadableNamesFromTheLocalPart() {
    assertThat(EndUserService.displayName(null, "ada.lovelace@x.com")).isEqualTo("Ada Lovelace");
    assertThat(EndUserService.displayName("  Grace  ", "g@x.com")).isEqualTo("Grace");
    assertThat(EndUserService.displayName("", "+@x.com")).isEqualTo("+@x.com");
  }
}
