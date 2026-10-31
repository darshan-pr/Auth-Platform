package com.authplatform.search;

import java.util.List;
import java.util.UUID;

public final class SearchDtos {
  private SearchDtos() {}

  public enum Type {
    ACCOUNT,
    APPLICATION,
    END_USER,
    AUDIT_EVENT
  }

  /** One matching resource; the frontend decides where it links to. */
  public record Hit(
      Type type,
      String id,
      String title,
      String subtitle,
      String status,
      UUID appId,
      String appName) {}

  public record Group(Type type, List<Hit> items, boolean hasMore) {}

  public record Response(String query, List<Group> groups) {}
}
