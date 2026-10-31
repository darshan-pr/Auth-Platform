package com.authplatform.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authplatform.common.exception.ApiException;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.user.entity.Account;
import com.authplatform.user.entity.AppUser;
import com.authplatform.app.entity.App;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

class MfaServiceTest {
  private final Map<String, String> redisValues = new HashMap<>();
  private final Map<String, Long> counters = new HashMap<>();
  private final AtomicReference<String> emailBody = new AtomicReference<>();
  private final AtomicInteger emailsSent = new AtomicInteger();
  private MfaService mfa;

  @SuppressWarnings("unchecked")
  @BeforeEach
  void setUp() {
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    ValueOperations<String, String> values = mock(ValueOperations.class);
    when(redis.opsForValue()).thenReturn(values);
    when(values.get(anyString()))
        .thenAnswer(invocation -> redisValues.get(invocation.getArgument(0)));
    when(values.increment(anyString()))
        .thenAnswer(invocation -> counters.merge(invocation.getArgument(0), 1L, Long::sum));
    doAnswer(
            invocation -> {
              redisValues.put(invocation.getArgument(0), invocation.getArgument(1));
              return null;
            })
        .when(values)
        .set(anyString(), anyString(), any(Duration.class));
    when(redis.expire(anyString(), any(Duration.class))).thenReturn(true);
    when(redis.delete(anyString()))
        .thenAnswer(invocation -> redisValues.remove(invocation.getArgument(0)) != null);

    EmailSender email =
        (to, subject, message) -> {
          emailBody.set(message);
          emailsSent.incrementAndGet();
        };
    mfa = new MfaService(redis, email, new EmailTemplateService(""));
  }

  @Test
  void passwordResetOtpIsFlowBoundAndCanBeVerified() {
    UUID accountId = UUID.randomUUID();
    Account account = mock(Account.class);
    when(account.getId()).thenReturn(accountId);
    when(account.getName()).thenReturn("Ada");

    var challenge = mfa.issueConsolePasswordResetOtp(account, "person@example.com");
    assertThat(emailBody.get()).contains("Hello Ada,");
    String firstCode = codeFromEmail();

    assertThatThrownBy(() -> mfa.resendConsoleAccountOtp(challenge.challengeId()))
        .isInstanceOf(ApiException.class);

    mfa.resendConsolePasswordResetOtp(challenge.challengeId());
    assertThat(emailBody.get()).contains("Hello Ada,");
    String resentCode = codeFromEmail();

    assertThat(mfa.verifyConsolePasswordResetOtp(challenge.challengeId(), resentCode))
        .isEqualTo(accountId);
    assertThat(firstCode).matches("\\d{6}");
    assertThat(emailsSent).hasValue(2);
  }

  @Test
  void unknownPasswordResetAddressDoesNotReceiveEmailOnResend() {
    var challenge = mfa.issueConsolePasswordResetOtp(null, "unknown@example.com");

    assertThat(emailsSent).hasValue(0);
    mfa.resendConsolePasswordResetOtp(challenge.challengeId());
    assertThat(emailsSent).hasValue(0);
  }

  @Test
  void appUserNameIsIncludedAndPreservedWhenResendingOtp() {
    UUID appId = UUID.randomUUID();
    App app = mock(App.class);
    AppUser user = mock(AppUser.class);
    when(app.getId()).thenReturn(appId);
    when(app.getName()).thenReturn("Northstar");
    when(user.getId()).thenReturn(UUID.randomUUID());
    when(user.getEmail()).thenReturn("person@example.com");
    when(user.getName()).thenReturn("Sam");

    var challenge = mfa.issueAppUserOtp(app, user);
    assertThat(emailBody.get()).contains("Hello Sam,");
    assertThat(codeFromEmail()).matches("\\d{6}");

    mfa.resendAppUserOtp(app, challenge.challengeId());

    assertThat(emailBody.get()).contains("Hello Sam,");
    assertThat(codeFromEmail()).matches("\\d{6}");
    assertThat(emailsSent).hasValue(2);
  }

  private String codeFromEmail() {
    Matcher matcher = Pattern.compile("is (\\d{6})\\.").matcher(emailBody.get());
    assertThat(matcher.find()).isTrue();
    return matcher.group(1);
  }
}
