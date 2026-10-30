package com.authplatform.common.crypto;

public interface TokenHasher {
  String hash(String raw);
}
