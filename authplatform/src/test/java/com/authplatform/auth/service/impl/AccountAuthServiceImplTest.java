package com.authplatform.auth.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authplatform.audit.AuditService;
import com.authplatform.auth.entity.EmailToken;
import com.authplatform.auth.entity.EmailTokenType;
import com.authplatform.auth.service.JwtService;
import com.authplatform.auth.service.LoginAttemptService;
import com.authplatform.auth.service.MfaService;
import com.authplatform.auth.service.OneTimeTokenService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.authplatform.notification.EmailSender;
import com.authplatform.notification.EmailTemplateService;
import com.authplatform.user.repository.AccountRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AccountAuthServiceImplTest {
  @Test
  void anEndUsersVerificationTokenIsRejectedInsteadOfCrashing() {
    AccountRepository accounts = mock(AccountRepository.class);
    OneTimeTokenService tokens = mock(OneTimeTokenService.class);
    EmailSender email = mock(EmailSender.class);
    AccountAuthServiceImpl service =
        new AccountAuthServiceImpl(
            accounts,
            mock(PasswordHasher.class),
            tokens,
            mock(SessionService.class),
            mock(JwtService.class),
            mock(LoginAttemptService.class),
            email,
            new EmailTemplateService(""),
            mock(AuditService.class),
            mock(MfaService.class));
    EmailToken appUserToken =
        EmailToken.forAppUser(
            UUID.randomUUID(), EmailTokenType.VERIFY_EMAIL, "hash", Instant.now().plusSeconds(60));
    when(tokens.consume("raw", EmailTokenType.VERIFY_EMAIL)).thenReturn(appUserToken);

    assertThatThrownBy(() -> service.verify("raw"))
        .isInstanceOfSatisfying(
            ApiException.class, ex -> assertThat(ex.code()).isEqualTo(ErrorCode.TOKEN_INVALID));
    verify(accounts, never()).findById(org.mockito.ArgumentMatchers.any());
  }
}
