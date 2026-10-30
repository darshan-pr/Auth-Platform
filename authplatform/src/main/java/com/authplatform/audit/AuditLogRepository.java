package com.authplatform.audit;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
  Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

  List<AuditLog> findAllByActorAppUserIdOrderByCreatedAtDesc(java.util.UUID actorAppUserId);
}
