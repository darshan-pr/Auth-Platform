package com.authplatform.search;

import com.authplatform.search.SearchDtos.Hit;
import com.authplatform.search.SearchDtos.Type;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Repository;

/**
 * Read-only lookups for global search. Queries select only the displayed columns (applications
 * carry large icon blobs) and fetch one extra row so callers can tell when more matches exist.
 */
@Repository
class SearchRepository {
  private static final String LIKE_ESCAPE = " escape '\\'";
  private static final UUID NO_ID = new UUID(0, 0);

  @PersistenceContext private EntityManager em;

  List<Hit> accounts(Pattern p, int limit) {
    return em
        .createQuery(
            "select a.id, a.name, a.email, a.status from Account a"
                + " where lower(a.name) like :contains"
                + LIKE_ESCAPE
                + " or lower(a.email) like :contains"
                + LIKE_ESCAPE
                + " or a.id = :id"
                + " order by case when lower(a.email) like :prefix"
                + LIKE_ESCAPE
                + " or lower(a.name) like :prefix"
                + LIKE_ESCAPE
                + " then 0 else 1 end, lower(a.name), a.id",
            Object[].class)
        .setParameter("contains", p.contains())
        .setParameter("prefix", p.prefix())
        .setParameter("id", p.id())
        .setMaxResults(limit + 1)
        .getResultList()
        .stream()
        .map(r -> new Hit(Type.ACCOUNT, r[0].toString(), (String) r[1], (String) r[2], (String) r[3], null, null))
        .toList();
  }

  List<Hit> applications(Pattern p, UUID owner, int limit) {
    var query =
        em.createQuery(
            "select a.id, a.name, a.status, a.publishableKey from App a where"
                + (owner == null ? " 1 = 1" : " a.ownerAccountId = :owner")
                + " and (lower(a.name) like :contains"
                + LIKE_ESCAPE
                + " or a.id = :id or a.publishableKey = :raw)"
                + " order by case when lower(a.name) like :prefix"
                + LIKE_ESCAPE
                + " then 0 else 1 end, lower(a.name), a.id",
            Object[].class);
    if (owner != null) query.setParameter("owner", owner);
    return query
        .setParameter("contains", p.contains())
        .setParameter("prefix", p.prefix())
        .setParameter("id", p.id())
        .setParameter("raw", p.raw())
        .setMaxResults(limit + 1)
        .getResultList()
        .stream()
        .map(
            r ->
                new Hit(
                    Type.APPLICATION,
                    r[0].toString(),
                    (String) r[1],
                    (String) r[3],
                    (String) r[2],
                    (UUID) r[0],
                    (String) r[1]))
        .toList();
  }

  List<Hit> endUsers(Pattern p, UUID owner, int limit) {
    var query =
        em.createQuery(
            "select u.id, u.name, u.email, u.status, a.id, a.name from AppUser u, App a"
                + " where a.id = u.appId"
                + (owner == null ? "" : " and a.ownerAccountId = :owner")
                + " and (lower(u.name) like :contains"
                + LIKE_ESCAPE
                + " or lower(u.email) like :contains"
                + LIKE_ESCAPE
                + " or u.id = :id)"
                + " order by case when lower(u.email) like :prefix"
                + LIKE_ESCAPE
                + " or lower(u.name) like :prefix"
                + LIKE_ESCAPE
                + " then 0 else 1 end, lower(u.name), u.id",
            Object[].class);
    if (owner != null) query.setParameter("owner", owner);
    return query
        .setParameter("contains", p.contains())
        .setParameter("prefix", p.prefix())
        .setParameter("id", p.id())
        .setMaxResults(limit + 1)
        .getResultList()
        .stream()
        .map(
            r ->
                new Hit(
                    Type.END_USER,
                    r[0].toString(),
                    (String) r[1],
                    (String) r[2],
                    (String) r[3],
                    (UUID) r[4],
                    (String) r[5]))
        .toList();
  }

  /** Recent audit events by action name (LOGIN_FAILED) or exact request id. */
  List<Hit> auditEvents(Pattern p, Instant since, int limit) {
    return em
        .createQuery(
            "select l.id, l.action, l.actorType, l.requestId from AuditLog l"
                + " where l.createdAt >= :since and (l.action like :action"
                + LIKE_ESCAPE
                + " or l.requestId = :raw) order by l.id desc",
            Object[].class)
        .setParameter("since", since)
        .setParameter("action", p.action())
        .setParameter("raw", p.raw())
        .setMaxResults(limit + 1)
        .getResultList()
        .stream()
        .map(
            r ->
                new Hit(
                    Type.AUDIT_EVENT,
                    r[0].toString(),
                    (String) r[1],
                    (String) r[2],
                    null,
                    null,
                    null))
        .toList();
  }

  /** Search text prepared once per request. */
  record Pattern(String contains, String prefix, String raw, String action, UUID id) {
    static Pattern of(String normalized) {
      UUID id = NO_ID;
      try {
        id = UUID.fromString(normalized);
      } catch (IllegalArgumentException ignored) {
        // not an id
      }
      String escaped = com.authplatform.user.service.Like.escape(normalized);
      String actionText =
          com.authplatform.user.service.Like.escape(
              normalized.toUpperCase(java.util.Locale.ROOT).replaceAll("\\s+", "_"));
      return new Pattern("%" + escaped + "%", escaped + "%", normalized, "%" + actionText + "%", id);
    }
  }
}
