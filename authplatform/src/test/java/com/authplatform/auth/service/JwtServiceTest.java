package com.authplatform.auth.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.List;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JwtServiceTest {
  @TempDir Path tempDir;

  @Test
  void configuredKeyRingKeepsTokensVerifiableAcrossServiceInstances() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();
    String configured =
        "stable|"
            + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded())
            + "|"
            + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());

    JwtService issuer =
        new JwtService(
            "https://issuer.example",
            Duration.ofMinutes(5),
            configured,
            "stable",
            "prod",
            tempDir.resolve("unused-key-file").toString());
    JwtService verifier =
        new JwtService(
            "https://issuer.example",
            Duration.ofMinutes(5),
            configured,
            "stable",
            "prod",
            tempDir.resolve("unused-key-file").toString());

    String token =
        issuer.issueForAudience(UUID.randomUUID(), UUID.randomUUID(), "USER", "audience");

    assertThat(verifier.parse(token, "audience").getIssuer()).isEqualTo("https://issuer.example");
  }

  @Test
  void developmentSigningKeyRemainsStableAcrossServiceRestarts() {
    String keyFile = tempDir.resolve("dev-signing-key").toString();
    JwtService first =
        new JwtService("https://issuer.example", Duration.ofMinutes(5), "", "dev", "dev", keyFile);
    String token = first.issueForAudience(UUID.randomUUID(), UUID.randomUUID(), "USER", "audience");

    JwtService restarted =
        new JwtService("https://issuer.example", Duration.ofMinutes(5), "", "dev", "dev", keyFile);

    assertThat(restarted.parse(token, "audience").getIssuer()).isEqualTo("https://issuer.example");
  }

  @Test
  void appTokenLifetimeOverridesThePlatformDefault() throws Exception {
    JwtService service =
        new JwtService(
            "https://issuer.example",
            Duration.ofMinutes(15),
            "",
            "dev",
            "dev",
            tempDir.resolve("custom-ttl-signing-key").toString());
    UUID subject = UUID.randomUUID();
    UUID audience = UUID.randomUUID();
    UUID sessionId = UUID.randomUUID();

    String token =
        service.issue(
            subject,
            audience,
            sessionId,
            null,
            List.of("member"),
            List.of("profile:read"),
            Duration.ofMinutes(2));
    var claims = service.parse(token, audience.toString());

    assertThat(
            Duration.between(
                    claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant())
                .toSeconds())
        .isEqualTo(120);
  }
}
