package com.authplatform.app.repository;

import com.authplatform.app.entity.App;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRepository extends JpaRepository<App, UUID> {
  List<App> findAllByOwnerAccountIdOrderByCreatedAtDesc(UUID ownerAccountId);

  Page<App> findAllByOwnerAccountId(UUID ownerAccountId, Pageable pageable);

  Optional<App> findByIdAndOwnerAccountId(UUID id, UUID ownerAccountId);

  Optional<App> findByPublishableKey(String publishableKey);

  long countByOwnerAccountId(UUID ownerAccountId);

  List<App> findAllByOrderByCreatedAtDesc();

  long countByStatus(String status);
}
