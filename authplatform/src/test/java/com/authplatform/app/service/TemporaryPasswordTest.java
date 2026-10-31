package com.authplatform.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TemporaryPasswordTest {
  @Test
  void generatesStrongUniquePasswordsWithoutAmbiguousCharacters() {
    Set<String> seen = new HashSet<>();
    for (int i = 0; i < 500; i++) {
      String password = TemporaryPassword.generate();
      assertThat(password).hasSize(14).matches(".*[A-Z].*").matches(".*[a-z].*").matches(".*\\d.*");
      assertThat(password).doesNotContainPattern("[0O1lI]");
      seen.add(password);
    }
    assertThat(seen).hasSize(500);
  }
}
