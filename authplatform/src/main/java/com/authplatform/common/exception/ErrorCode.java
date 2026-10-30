package com.authplatform.common.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
  VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "Request validation failed"),
  TOKEN_INVALID(HttpStatus.BAD_REQUEST, "Token is invalid"),
  UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "Authentication is required"),
  INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Email or password is incorrect"),
  INVALID_KEY(HttpStatus.UNAUTHORIZED, "Application key is invalid"),
  EMAIL_NOT_VERIFIED(HttpStatus.FORBIDDEN, "Email is not verified"),
  ACCESS_DENIED(HttpStatus.FORBIDDEN, "Access denied"),
  ORIGIN_NOT_ALLOWED(HttpStatus.FORBIDDEN, "Origin is not allowed"),
  APP_SUSPENDED(HttpStatus.FORBIDDEN, "Application is suspended"),
  USER_BLOCKED(HttpStatus.FORBIDDEN, "User is blocked"),
  NOT_FOUND(HttpStatus.NOT_FOUND, "Resource not found"),
  EMAIL_TAKEN(HttpStatus.CONFLICT, "Email is already registered"),
  ROLE_NAME_TAKEN(HttpStatus.CONFLICT, "Role name is already registered"),
  APP_LIMIT_REACHED(HttpStatus.CONFLICT, "Application limit reached"),
  ACCOUNT_LOCKED(HttpStatus.LOCKED, "Account is temporarily locked"),
  MFA_REQUIRED(HttpStatus.UNAUTHORIZED, "A one-time password is required"),
  MFA_INVALID(HttpStatus.UNAUTHORIZED, "The one-time password is invalid"),
  OTP_EXPIRED(HttpStatus.BAD_REQUEST, "The one-time password has expired"),
  REFRESH_IN_PROGRESS(HttpStatus.CONFLICT, "A session refresh is already completing"),
  RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "Too many requests"),
  RATE_LIMIT_UNAVAILABLE(
      HttpStatus.SERVICE_UNAVAILABLE, "Authentication protection is temporarily unavailable"),
  INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");
  private final HttpStatus status;
  private final String message;

  ErrorCode(HttpStatus status, String message) {
    this.status = status;
    this.message = message;
  }

  public HttpStatus status() {
    return status;
  }

  public String message() {
    return message;
  }
}
