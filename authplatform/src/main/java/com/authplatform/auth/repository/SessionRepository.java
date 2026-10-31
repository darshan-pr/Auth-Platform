package com.authplatform.auth.repository;

import com.authplatform.auth.entity.Session;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SessionRepository extends JpaRepository<Session, UUID> {
  Optional<Session> findByRefreshTokenHash(String hash);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select s from Session s where s.refreshTokenHash = :hash")
  Optional<Session> findByRefreshTokenHashForUpdate(@Param("hash") String hash);

  @Query("select s from Session s join s.usedRefreshTokenHashes h where h = :hash")
  Optional<Session> findByUsedRefreshTokenHash(@Param("hash") String hash);

  List<Session> findAllByRevokedAtAfter(Instant revokedAt);

  List<Session> findAllByAccountIdAndRevokedAtIsNull(UUID accountId);

  List<Session> findAllByAppUserIdAndRevokedAtIsNull(UUID appUserId);
}
