package com.authplatform.user.repository;

import com.authplatform.user.entity.AppUser;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
  Optional<AppUser> findByAppIdAndEmailIgnoreCase(UUID appId, String email);

  Optional<AppUser> findByAppIdAndId(UUID appId, UUID id);

  boolean existsByAppIdAndEmailIgnoreCase(UUID appId, String email);

  List<AppUser> findAllByAppIdOrderByCreatedAtDesc(UUID appId);

  Page<AppUser> findAllByAppId(UUID appId, Pageable pageable);

  @Query("select u from AppUser u where u.appId = :appId and lower(u.email) in :emails")
  List<AppUser> findAllByAppIdAndLowerEmailIn(
      @Param("appId") UUID appId, @Param("emails") java.util.Collection<String> emails);

  // An empty pattern/status means "no filter"; parameters are never null so Postgres can type them.
  String FILTERS =
      " and (:pattern = '' or lower(u.name) like :pattern escape '\\' or lower(u.email) like :pattern escape '\\')"
          + " and (:status = '' or u.status = :status)"
          + " and (:invitedOnly = false or (u.invitedAt is not null and u.lastLoginAt is null))"
          + " and (:unverifiedOnly = false or u.emailVerified = false)";

  @Query(
      value = "select u from AppUser u where u.appId = :appId" + FILTERS,
      countQuery = "select count(u) from AppUser u where u.appId = :appId" + FILTERS)
  Page<AppUser> search(
      @Param("appId") UUID appId,
      @Param("pattern") String pattern,
      @Param("status") String status,
      @Param("invitedOnly") boolean invitedOnly,
      @Param("unverifiedOnly") boolean unverifiedOnly,
      Pageable pageable);

  @Query(
      value = "select u from AppUser u where 1 = 1" + FILTERS,
      countQuery = "select count(u) from AppUser u where 1 = 1" + FILTERS)
  Page<AppUser> searchAll(
      @Param("pattern") String pattern,
      @Param("status") String status,
      @Param("invitedOnly") boolean invitedOnly,
      @Param("unverifiedOnly") boolean unverifiedOnly,
      Pageable pageable);

  long countByAppId(UUID appId);

  long countByStatus(String status);

  long countByEmailVerifiedTrue();
}
