package com.authplatform.common.crypto.impl;

import com.authplatform.common.crypto.PasswordHasher;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class Argon2PasswordHasher implements PasswordHasher {
  private final Argon2PasswordEncoder encoder =
      Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

  public String hash(String raw) {
    return encoder.encode(raw);
  }

  public boolean matches(String raw, String encoded) {
    return encoder.matches(raw, encoded);
  }
}
