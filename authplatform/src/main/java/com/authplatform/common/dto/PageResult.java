package com.authplatform.common.dto;

import java.util.List;
import org.springframework.data.domain.Page;

public record PageResult<T>(List<T> items, int page, int size, long totalItems, int totalPages) {
  public static <T> PageResult<T> of(Page<T> page) {
    return new PageResult<>(
        page.getContent(),
        page.getNumber(),
        page.getSize(),
        page.getTotalElements(),
        page.getTotalPages());
  }
}
