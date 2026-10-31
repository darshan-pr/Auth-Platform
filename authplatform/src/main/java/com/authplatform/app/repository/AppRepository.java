package com.authplatform.app.repository;

import com.authplatform.app.entity.App;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AppRepository extends JpaRepository<App, UUID> {
  List<App> findAllByOwnerAccountIdOrderByCreatedAtDesc(UUID ownerAccountId);

  Page<App> findAllByOwnerAccountId(UUID ownerAccountId, Pageable pageable);

  @Query(
      value =
          "select a from App a where a.ownerAccountId = :owner"
              + " and (:pattern = '' or lower(a.name) like :pattern escape '\\')",
      countQuery =
          "select count(a) from App a where a.ownerAccountId = :owner"
              + " and (:pattern = '' or lower(a.name) like :pattern escape '\\')")
  Page<App> search(
      @Param("owner") UUID owner, @Param("pattern") String pattern, Pageable pageable);

  Optional<App> findByIdAndOwnerAccountId(UUID id, UUID ownerAccountId);

  Optional<App> findByPublishableKey(String publishableKey);

  long countByOwnerAccountId(UUID ownerAccountId);

  List<App> findAllByOrderByCreatedAtDesc();

  long countByStatus(String status);
}
