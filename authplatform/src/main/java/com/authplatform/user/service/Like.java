package com.authplatform.user.service;

import java.util.Locale;

/** Builds safe, case-insensitive LIKE patterns from user-typed search text. */
public final class Like {
  public static final int MAX_QUERY_LENGTH = 100;

  private Like() {}

  /** Returns {@code %text%} with wildcards escaped, or an empty string for blank input. */
  public static String contains(String query) {
    String text = normalize(query);
    return text.isEmpty() ? "" : "%" + escape(text) + "%";
  }

  /** Returns {@code text%} with wildcards escaped, or an empty string for blank input. */
  public static String prefix(String query) {
    String text = normalize(query);
    return text.isEmpty() ? "" : escape(text) + "%";
  }

  public static String normalize(String query) {
    if (query == null) return "";
    String text = query.strip().toLowerCase(Locale.ROOT);
    return text.length() > MAX_QUERY_LENGTH ? text.substring(0, MAX_QUERY_LENGTH) : text;
  }

  public static String escape(String text) {
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
  }
}
