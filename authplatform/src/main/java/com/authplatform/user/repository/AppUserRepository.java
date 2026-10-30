package com.authplatform.user.repository;

import com.authplatform.user.entity.AppUser;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
  Optional<AppUser> findByAppIdAndEmailIgnoreCase(UUID appId, String email);

  Optional<AppUser> findByAppIdAndId(UUID appId, UUID id);

  boolean existsByAppIdAndEmailIgnoreCase(UUID appId, String email);

  List<AppUser> findAllByAppIdOrderByCreatedAtDesc(UUID appId);

  Page<AppUser> findAllByAppId(UUID appId, Pageable pageable);

  long countByAppId(UUID appId);

  long countByStatus(String status);

  long countByEmailVerifiedTrue();
}
