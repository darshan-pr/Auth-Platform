package com.authplatform.common.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class MfaSecretProtector {
  private static final String PREFIX = "v1:";
  private final SecretKeySpec key;
  private final SecureRandom random = new SecureRandom();

  public MfaSecretProtector(
      @Value("${authplatform.security.key-encryption-secret}") String encryptionSecret) {
    try {
      key =
          new SecretKeySpec(
              MessageDigest.getInstance("SHA-256")
                  .digest(encryptionSecret.getBytes(StandardCharsets.UTF_8)),
              "AES");
    } catch (Exception ex) {
      throw new IllegalStateException("Unable to initialize MFA secret protection", ex);
    }
  }

  public String protect(String value) {
    try {
      byte[] nonce = new byte[12];
      random.nextBytes(nonce);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
      byte[] ciphertext = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
      return PREFIX
          + Base64.getUrlEncoder().withoutPadding().encodeToString(nonce)
          + ":"
          + Base64.getUrlEncoder().withoutPadding().encodeToString(ciphertext);
    } catch (Exception ex) {
      throw new IllegalStateException("Unable to protect MFA secret", ex);
    }
  }

  public String reveal(String value) {
    try {
      if (value == null || !value.startsWith(PREFIX))
        throw new IllegalArgumentException("Invalid MFA secret");
      String[] parts = value.substring(PREFIX.length()).split(":", 2);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          key,
          new GCMParameterSpec(128, Base64.getUrlDecoder().decode(parts[0])));
      return new String(
          cipher.doFinal(Base64.getUrlDecoder().decode(parts[1])), StandardCharsets.UTF_8);
    } catch (Exception ex) {
      throw new IllegalStateException("Unable to reveal MFA secret", ex);
    }
  }
}
