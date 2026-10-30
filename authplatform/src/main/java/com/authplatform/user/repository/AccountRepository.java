package com.authplatform.user.repository;

import com.authplatform.user.entity.Account;
import com.authplatform.user.entity.PlatformRole;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository extends JpaRepository<Account, UUID> {
  Optional<Account> findByEmailIgnoreCase(String email);

  boolean existsByEmailIgnoreCase(String email);

  long countByPlatformRole(PlatformRole platformRole);

  long countByStatus(String status);

  long countByEmailVerifiedTrue();
}
