package com.authplatform.search;

import com.authplatform.search.SearchDtos.Group;
import com.authplatform.search.SearchDtos.Hit;
import com.authplatform.search.SearchDtos.Response;
import com.authplatform.search.SearchDtos.Type;
import com.authplatform.user.service.Like;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SearchService {
  static final int MIN_QUERY_LENGTH = 2;
  static final int DEFAULT_LIMIT = 5;
  static final int MAX_LIMIT = 10;
  private static final Duration AUDIT_WINDOW = Duration.ofDays(30);

  private final SearchRepository repository;

  SearchService(SearchRepository repository) {
    this.repository = repository;
  }

  /** Everything on the platform; callers must already be authorized as SA. */
  @Transactional(readOnly = true)
  public Response searchPlatform(String query, int limit) {
    String text = Like.normalize(query);
    if (text.length() < MIN_QUERY_LENGTH) return new Response(text, List.of());
    int size = clamp(limit);
    SearchRepository.Pattern pattern = SearchRepository.Pattern.of(text);
    List<Group> groups = new ArrayList<>();
    add(groups, Type.ACCOUNT, repository.accounts(pattern, size), size);
    add(groups, Type.APPLICATION, repository.applications(pattern, null, size), size);
    add(groups, Type.END_USER, repository.endUsers(pattern, null, size), size);
    add(
        groups,
        Type.AUDIT_EVENT,
        repository.auditEvents(pattern, Instant.now().minus(AUDIT_WINDOW), size),
        size);
    return new Response(text, groups);
  }

  /** Only the applications owned by {@code owner} and the end users inside them. */
  @Transactional(readOnly = true)
  public Response searchOwned(UUID owner, String query, int limit) {
    String text = Like.normalize(query);
    if (text.length() < MIN_QUERY_LENGTH) return new Response(text, List.of());
    int size = clamp(limit);
    SearchRepository.Pattern pattern = SearchRepository.Pattern.of(text);
    List<Group> groups = new ArrayList<>();
    add(groups, Type.APPLICATION, repository.applications(pattern, owner, size), size);
    add(groups, Type.END_USER, repository.endUsers(pattern, owner, size), size);
    return new Response(text, groups);
  }

  private static void add(List<Group> groups, Type type, List<Hit> hits, int size) {
    if (hits.isEmpty()) return;
    boolean more = hits.size() > size;
    groups.add(new Group(type, more ? hits.subList(0, size) : hits, more));
  }

  private static int clamp(int limit) {
    return limit <= 0 ? DEFAULT_LIMIT : Math.min(limit, MAX_LIMIT);
  }
}
