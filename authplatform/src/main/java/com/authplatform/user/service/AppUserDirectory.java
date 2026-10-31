package com.authplatform.user.service;

import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AppUserRepository;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Server-side search, filter, sort and paging shared by the console and SA end-user lists. */
@Service
public class AppUserDirectory {
  public static final int MAX_PAGE_SIZE = 100;
  private static final Set<String> SORTABLE =
      Set.of("name", "email", "status", "emailVerified", "lastLoginAt", "createdAt");
  private static final Set<String> STATUSES = Set.of("ACTIVE", "SUSPENDED", "BLOCKED");

  private final AppUserRepository users;

  public AppUserDirectory(AppUserRepository users) {
    this.users = users;
  }

  /** {@code appId == null} searches every application (SA only). */
  @Transactional(readOnly = true)
  public Page<AppUser> search(
      UUID appId, String query, String status, String sort, String direction, int page, int size) {
    String pattern = Like.contains(query);
    String filter = status == null ? "" : status.trim().toUpperCase(Locale.ROOT);
    boolean invited = filter.equals("INVITED");
    boolean unverified = filter.equals("UNVERIFIED");
    String exactStatus = invited ? "ACTIVE" : STATUSES.contains(filter) ? filter : "";
    PageRequest pageable = pageRequest(sort, direction, page, size);
    return appId == null
        ? users.searchAll(pattern, exactStatus, invited, unverified, pageable)
        : users.search(appId, pattern, exactStatus, invited, unverified, pageable);
  }

  static PageRequest pageRequest(String sort, String direction, int page, int size) {
    int safeSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
    int safePage = Math.max(page, 0);
    if (sort == null || !SORTABLE.contains(sort)) {
      return PageRequest.of(
          safePage, safeSize, Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id")));
    }
    Sort.Order order =
        "desc".equalsIgnoreCase(direction) ? Sort.Order.desc(sort) : Sort.Order.asc(sort);
    if (sort.equals("name") || sort.equals("email")) order = order.ignoreCase();
    if (sort.equals("lastLoginAt")) order = order.nullsLast();
    return PageRequest.of(safePage, safeSize, Sort.by(order, Sort.Order.asc("id")));
  }
}
