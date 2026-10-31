package com.authplatform.app.service;

import com.authplatform.sa.dto.SaDtos;
import com.authplatform.user.service.Like;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Platform-wide application list for SA with server-side search, sorting and paging. It selects
 * only the displayed columns (icons are large blobs) and counts end users in the same query
 * instead of issuing one lookup per row.
 */
@Service
public class AppDirectory {
  public static final int MAX_PAGE_SIZE = 100;
  private static final Map<String, String> SORT =
      Map.of(
          "name", "lower(a.name)",
          "ownerEmail", "lower(o.email)",
          "status", "a.status",
          "userCount", "(select count(u) from AppUser u where u.appId = a.id)",
          "createdAt", "a.createdAt");
  private static final String FROM = " from App a left join Account o on o.id = a.ownerAccountId";
  private static final String WHERE =
      " where (:pattern = '' or lower(a.name) like :pattern escape '\\'"
          + " or lower(o.email) like :pattern escape '\\' or a.publishableKey = :raw)";

  @PersistenceContext private EntityManager em;

  @Transactional(readOnly = true)
  public Page<SaDtos.AppView> search(
      String query, String sort, String direction, int page, int size) {
    int safeSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
    PageRequest pageable = PageRequest.of(Math.max(page, 0), safeSize);
    String text = Like.normalize(query);
    String pattern = Like.contains(text);
    String column = SORT.get(sort);
    String order =
        column == null
            ? "a.createdAt desc"
            : column + ("desc".equalsIgnoreCase(direction) ? " desc" : " asc");
    long total =
        em.createQuery("select count(a)" + FROM + WHERE, Long.class)
            .setParameter("pattern", pattern)
            .setParameter("raw", query == null ? "" : query.strip())
            .getSingleResult();
    List<Object[]> rows =
        em.createQuery(
                "select a.id, a.name, a.publishableKey, a.ownerAccountId, o.email, a.allowedOrigins,"
                    + " a.requireEmailVerification, a.mfaRequired, a.status, a.createdAt,"
                    + " a.secretKeyHint, (select count(u) from AppUser u where u.appId = a.id),"
                    + " a.accessTokenTtlSeconds, a.refreshTokenTtlSeconds"
                    + FROM
                    + WHERE
                    + " order by "
                    + order
                    + ", a.id",
                Object[].class)
            .setParameter("pattern", pattern)
            .setParameter("raw", query == null ? "" : query.strip())
            .setFirstResult((int) pageable.getOffset())
            .setMaxResults(safeSize)
            .getResultList();
    return new PageImpl<>(rows.stream().map(AppDirectory::view).toList(), pageable, total);
  }

  private static SaDtos.AppView view(Object[] r) {
    return new SaDtos.AppView(
        (UUID) r[0],
        (String) r[1],
        (String) r[2],
        (UUID) r[3],
        (String) r[4],
        r[5] == null ? List.of() : Arrays.asList((String[]) r[5]),
        (Boolean) r[6],
        (Boolean) r[7],
        (String) r[8],
        (Instant) r[9],
        (String) r[10],
        ((Number) r[11]).longValue(),
        (Integer) r[12],
        (Integer) r[13]);
  }
}
