package com.authplatform.user.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Sort;

class LikeAndDirectoryTest {
  @Test
  void escapesWildcardsAndLowercases() {
    assertThat(Like.contains("  50%_Off\\ ")).isEqualTo("%50\\%\\_off\\\\%");
    assertThat(Like.prefix("Ab")).isEqualTo("ab%");
    assertThat(Like.contains("   ")).isEmpty();
    assertThat(Like.contains(null)).isEmpty();
    assertThat(Like.normalize("x".repeat(500))).hasSize(Like.MAX_QUERY_LENGTH);
  }

  @Test
  void whitelistsSortColumnsAndCapsPageSize() {
    var byName = AppUserDirectory.pageRequest("name", "desc", 2, 1000);
    assertThat(byName.getPageSize()).isEqualTo(AppUserDirectory.MAX_PAGE_SIZE);
    assertThat(byName.getPageNumber()).isEqualTo(2);
    Sort.Order order = byName.getSort().getOrderFor("name");
    assertThat(order.isDescending()).isTrue();
    assertThat(order.isIgnoreCase()).isTrue();

    var unknown = AppUserDirectory.pageRequest("password_hash", "asc", -5, 0);
    assertThat(unknown.getPageNumber()).isZero();
    assertThat(unknown.getPageSize()).isEqualTo(1);
    assertThat(unknown.getSort().getOrderFor("createdAt").isDescending()).isTrue();
    assertThat(unknown.getSort().getOrderFor("password_hash")).isNull();

    var lastLogin = AppUserDirectory.pageRequest("lastLoginAt", "asc", 0, 20);
    assertThat(lastLogin.getSort().getOrderFor("lastLoginAt").getNullHandling())
        .isEqualTo(Sort.NullHandling.NULLS_LAST);
  }
}
