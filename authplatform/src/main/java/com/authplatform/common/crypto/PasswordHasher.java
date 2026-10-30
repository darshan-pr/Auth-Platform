package com.authplatform.common.crypto;

public interface PasswordHasher {
  String hash(String raw);

  boolean matches(String raw, String encoded);
}
