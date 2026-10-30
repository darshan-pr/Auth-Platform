package com.authplatform.common.crypto;

public interface SecureTokenGenerator {
  String generate();

  String generatePublishableKey();

  String generateSecretKey();
}
