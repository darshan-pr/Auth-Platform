package com.authplatform.common.exception;

import com.authplatform.common.dto.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @Value("${authplatform.security.cookie-secure:false}")
  private boolean secureCookies;

  @ExceptionHandler(ApiException.class)
  ResponseEntity<ApiError> handle(ApiException ex, HttpServletRequest request) {
    return body(ex.code(), ex.getMessage(), request, List.of());
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  ResponseEntity<ApiError> handleValidation(
      MethodArgumentNotValidException ex, HttpServletRequest request) {
    List<ApiError.FieldError> fields =
        ex.getBindingResult().getFieldErrors().stream()
            .map(e -> new ApiError.FieldError(e.getField(), e.getDefaultMessage()))
            .toList();
    return body(
        ErrorCode.VALIDATION_FAILED, ErrorCode.VALIDATION_FAILED.message(), request, fields);
  }

  @ExceptionHandler(Exception.class)
  ResponseEntity<ApiError> handleUnexpected(Exception ex, HttpServletRequest request) {
    log.error(
        "Unhandled request failure requestId={} path={}",
        request.getHeader("X-Request-Id"),
        request.getRequestURI(),
        ex);
    return body(ErrorCode.INTERNAL_ERROR, ErrorCode.INTERNAL_ERROR.message(), request, List.of());
  }

  private ResponseEntity<ApiError> body(
      ErrorCode code,
      String message,
      HttpServletRequest request,
      List<ApiError.FieldError> fields) {
    Object value = request.getAttribute("requestId");
    String id = value == null ? request.getHeader("X-Request-Id") : value.toString();
    ResponseEntity.BodyBuilder response = ResponseEntity.status(code.status());
    if (shouldClearSessionCookies(request.getRequestURI(), code)) {
      boolean sa = request.getRequestURI().startsWith("/api/sa/auth/");
      addExpiredCookie(
          response,
          sa ? "authplatform_sa_refresh" : "authplatform_refresh",
          sa ? "/api/sa/auth" : "/api/console/auth");
      addExpiredCookie(
          response,
          sa ? "authplatform_sa_access" : "authplatform_access",
          sa ? "/api/sa" : "/api/console");
    }
    return response.body(new ApiError(new ApiError.Error(code.name(), message, id, fields)));
  }

  private boolean shouldClearSessionCookies(String path, ErrorCode code) {
    boolean sa = path.startsWith("/api/sa/auth/");
    boolean console = path.startsWith("/api/console/auth/");
    if (!sa && !console) return false;
    if (path.endsWith("/logout")) return true;
    return path.endsWith("/refresh")
        && (code == ErrorCode.TOKEN_INVALID
            || code == ErrorCode.UNAUTHENTICATED
            || code == ErrorCode.USER_BLOCKED
            || code == ErrorCode.ACCOUNT_LOCKED);
  }

  private void addExpiredCookie(ResponseEntity.BodyBuilder response, String name, String path) {
    response.header(
        HttpHeaders.SET_COOKIE,
        ResponseCookie.from(name, "")
            .httpOnly(true)
            .secure(secureCookies)
            .sameSite("Strict")
            .path(path)
            .maxAge(Duration.ZERO)
            .build()
            .toString());
  }
}
