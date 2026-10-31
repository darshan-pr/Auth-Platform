package com.authplatform.auth.service;

import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class LoginAttemptService {
  private final StringRedisTemplate redis;
  private final int maxFailures;
  private final Duration window;
  private final Duration lockDuration;

  public LoginAttemptService(
      StringRedisTemplate redis,
      @Value("${authplatform.security.lockout-max-failures}") int maxFailures,
      @Value("${authplatform.security.lockout-window}") Duration window,
      @Value("${authplatform.security.lockout-duration}") Duration lockDuration) {
    this.redis = redis;
    this.maxFailures = maxFailures;
    this.window = window;
    this.lockDuration = lockDuration;
  }

  public void assertNotLocked(String key) {
    try {
      if (Boolean.TRUE.equals(redis.hasKey("authplatform:lock:" + key)))
        throw new ApiException(ErrorCode.ACCOUNT_LOCKED);
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }

  public boolean recordFailure(String key) {
    try {
      String countKey = "authplatform:lock:fail:" + key;
      String lockKey = "authplatform:lock:" + key;
      Long count = redis.opsForValue().increment(countKey);
      redis.expire(countKey, window);
      if (count != null
          && count >= maxFailures
          && !Boolean.TRUE.equals(redis.hasKey(lockKey))) {
        redis.opsForValue().set(lockKey, "1", lockDuration);
        return true;
      }
      return false;
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }

  public Duration lockDuration() {
    return lockDuration;
  }

  public void clearFailures(String key) {
    try {
      redis.delete("authplatform:lock:fail:" + key);
      redis.delete("authplatform:lock:" + key);
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.RATE_LIMIT_UNAVAILABLE);
    }
  }
}
