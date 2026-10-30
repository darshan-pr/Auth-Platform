package com.authplatform.common.crypto.impl;

import com.authplatform.common.crypto.SecureTokenGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Component;

@Component
public class SecureRandomTokenGenerator implements SecureTokenGenerator {
  private final SecureRandom random = new SecureRandom();

  public String generate() {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  public String generatePublishableKey() {
    return "pk_live_" + generate();
  }

  public String generateSecretKey() {
    return "sk_live_" + generate();
  }
}
