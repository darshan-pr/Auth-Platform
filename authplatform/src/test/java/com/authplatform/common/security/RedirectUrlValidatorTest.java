package com.authplatform.common.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class RedirectUrlValidatorTest {
  @Test
  void rejectsTokenExfiltrationUrlsWithExistingQueryOrUnsafeScheme() {
    assertThatThrownBy(() -> RedirectUrlValidator.validate("https://evil.example/reset?next=1"))
        .isInstanceOf(RuntimeException.class);
    assertThatThrownBy(() -> RedirectUrlValidator.validate("javascript:alert(1)"))
        .isInstanceOf(RuntimeException.class);
  }
}
