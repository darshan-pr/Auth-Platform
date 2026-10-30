package com.authplatform.auth.service;

import com.authplatform.auth.entity.EmailToken;
import com.authplatform.auth.entity.EmailTokenType;
import com.authplatform.auth.repository.EmailTokenRepository;
import com.authplatform.common.crypto.SecureTokenGenerator;
import com.authplatform.common.crypto.TokenHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OneTimeTokenService {
  private final EmailTokenRepository repository;
  private final SecureTokenGenerator generator;
  private final TokenHasher hasher;
  private final Duration verifyTtl;
  private final Duration resetTtl;

  public OneTimeTokenService(
      EmailTokenRepository repository,
      SecureTokenGenerator generator,
      TokenHasher hasher,
      @Value("${authplatform.security.verify-token-ttl}") Duration verifyTtl,
      @Value("${authplatform.security.reset-token-ttl}") Duration resetTtl) {
    this.repository = repository;
    this.generator = generator;
    this.hasher = hasher;
    this.verifyTtl = verifyTtl;
    this.resetTtl = resetTtl;
  }

  @Transactional
  public Issued issueAccount(UUID id, EmailTokenType type) {
    repository.deleteAllByAccountIdAndType(id, type);
    return issue(EmailToken.forAccount(id, type, "", expiry(type)));
  }

  @Transactional
  public Issued issueAppUser(UUID id, EmailTokenType type) {
    repository.deleteAllByAppUserIdAndType(id, type);
    return issue(EmailToken.forAppUser(id, type, "", expiry(type)));
  }

  private Issued issue(EmailToken token) {
    String raw = generator.generate();
    token =
        token.getAccountId() != null
            ? EmailToken.forAccount(
                token.getAccountId(), token.getType(), hasher.hash(raw), expiry(token.getType()))
            : EmailToken.forAppUser(
                token.getAppUserId(), token.getType(), hasher.hash(raw), expiry(token.getType()));
    repository.save(token);
    return new Issued(raw, token);
  }

  @Transactional
  public EmailToken consume(String raw, EmailTokenType type) {
    EmailToken token =
        repository
            .findByTokenHashAndType(hasher.hash(raw), type)
            .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID));
    if (!token.isUsable(Instant.now())) throw new ApiException(ErrorCode.TOKEN_INVALID);
    token.use(Instant.now());
    return token;
  }

  private Instant expiry(EmailTokenType type) {
    return Instant.now().plus(type == EmailTokenType.VERIFY_EMAIL ? verifyTtl : resetTtl);
  }

  public record Issued(String rawToken, EmailToken token) {}
}
