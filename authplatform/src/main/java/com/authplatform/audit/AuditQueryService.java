package com.authplatform.audit;

import com.authplatform.user.service.Like;
import java.util.Locale;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Paged, searchable audit history shared by the SA audit log and a single end user's history. */
@Service
public class AuditQueryService {
  private static final int MAX_PAGE_SIZE = 100;
  private static final UUID NO_ID = new UUID(0, 0);

  private final AuditLogRepository logs;

  public AuditQueryService(AuditLogRepository logs) {
    this.logs = logs;
  }

  /** {@code appUserId == null} returns events for everyone. */
  @Transactional(readOnly = true)
  public Page<AuditLog> search(String query, UUID appUserId, int page, int size) {
    PageRequest pageable =
        PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), MAX_PAGE_SIZE));
    String text = Like.normalize(query);
    if (text.isEmpty()) {
      return appUserId == null
          ? logs.findAllByOrderByCreatedAtDesc(pageable)
          : logs.findAllByActorAppUserIdOrderByCreatedAtDescIdDesc(appUserId, pageable);
    }
    String upper = text.toUpperCase(Locale.ROOT);
    String action = "%" + Like.escape(upper.replaceAll("\\s+", "_")) + "%";
    String contains = "%" + Like.escape(text) + "%";
    String prefix = Like.escape(text) + "%";
    UUID id = parseId(text);
    return appUserId == null
        ? logs.search(action, upper, contains, prefix, id, pageable)
        : logs.searchForAppUser(appUserId, action, upper, contains, prefix, id, pageable);
  }

  private static UUID parseId(String text) {
    try {
      return UUID.fromString(text);
    } catch (IllegalArgumentException ex) {
      return NO_ID;
    }
  }
}
