package com.authplatform.auth.repository;

import com.authplatform.auth.entity.EmailToken;
import com.authplatform.auth.entity.EmailTokenType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailTokenRepository extends JpaRepository<EmailToken, UUID> {
  Optional<EmailToken> findByTokenHashAndType(String tokenHash, EmailTokenType type);

  void deleteAllByAccountIdAndType(UUID accountId, EmailTokenType type);

  void deleteAllByAppUserIdAndType(UUID appUserId, EmailTokenType type);
}
