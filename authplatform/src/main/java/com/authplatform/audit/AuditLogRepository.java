package com.authplatform.audit;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
  Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

  String MATCH =
      "(upper(l.action) like :action escape '\\'"
          + " or upper(l.actorType) = :actorType or l.ipAddress like :contains escape '\\'"
          + " or l.requestId like :prefix escape '\\'"
          + " or l.actorAccountId = :id or l.actorAppUserId = :id)";

  /** Matches the action name, actor type, IP address, request id or an actor id. */
  @Query("select l from AuditLog l where " + MATCH + " order by l.createdAt desc, l.id desc")
  Page<AuditLog> search(
      @Param("action") String action,
      @Param("actorType") String actorType,
      @Param("contains") String contains,
      @Param("prefix") String prefix,
      @Param("id") java.util.UUID id,
      Pageable pageable);

  Page<AuditLog> findAllByActorAppUserIdOrderByCreatedAtDescIdDesc(
      java.util.UUID actorAppUserId, Pageable pageable);

  /** Same text search as {@link #search}, limited to one end user's own events. */
  @Query(
      "select l from AuditLog l where l.actorAppUserId = :userId and "
          + MATCH
          + " order by l.createdAt desc, l.id desc")
  Page<AuditLog> searchForAppUser(
      @Param("userId") java.util.UUID userId,
      @Param("action") String action,
      @Param("actorType") String actorType,
      @Param("contains") String contains,
      @Param("prefix") String prefix,
      @Param("id") java.util.UUID id,
      Pageable pageable);

  List<AuditLog> findAllByActorAppUserIdOrderByCreatedAtDesc(java.util.UUID actorAppUserId);
}
