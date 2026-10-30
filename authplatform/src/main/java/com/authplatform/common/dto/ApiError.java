package com.authplatform.common.dto;

import java.util.List;

public record ApiError(Error error) {
  public record Error(
      String code, String message, String requestId, List<FieldError> fieldErrors) {}

  public record FieldError(String field, String message) {}
}
