package com.authplatform.app.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.authplatform.common.exception.ApiException;
import org.junit.jupiter.api.Test;

class TokenLifetimePolicyTest {
  @Test
  void acceptsInheritedAndBoundedCustomLifetimes() {
    assertDoesNotThrow(() -> TokenLifetimePolicy.validatePair(null, null));
    assertDoesNotThrow(() -> TokenLifetimePolicy.validatePair(60, 3_600));
    assertDoesNotThrow(() -> TokenLifetimePolicy.validatePair(86_400, 86_400));
  }

  @Test
  void rejectsPartialOutOfRangeAndShorterRefreshLifetimes() {
    assertThrows(ApiException.class, () -> TokenLifetimePolicy.validatePair(300, null));
    assertThrows(ApiException.class, () -> TokenLifetimePolicy.validatePair(59, 3_600));
    assertThrows(ApiException.class, () -> TokenLifetimePolicy.validatePair(300, 3_599));
    assertThrows(ApiException.class, () -> TokenLifetimePolicy.validatePair(300, 299));
    assertThrows(ApiException.class, () -> TokenLifetimePolicy.validatePair(86_401, 86_401));
    assertThrows(ApiException.class, () -> TokenLifetimePolicy.validatePair(60, 7_776_001));
  }

  @Test
  void canRestorePlatformDefaultsOnlyWithoutCustomValues() {
    assertDoesNotThrow(() -> TokenLifetimePolicy.validateUpdate(null, null, true));
    assertThrows(
        ApiException.class,
        () -> TokenLifetimePolicy.validateUpdate(300, 3_600, true));
  }
}
