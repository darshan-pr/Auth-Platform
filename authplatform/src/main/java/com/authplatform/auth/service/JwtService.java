package com.authplatform.auth.service;

import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
  private static final Duration CLOCK_SKEW = Duration.ofSeconds(30);
  private final String issuer;
  private final Duration accessTtl;
  private final String activeKid;
  private final Map<String, RSAKey> keys;

  public JwtService(
      @Value("${authplatform.jwt.issuer}") String issuer,
      @Value("${authplatform.jwt.access-token-ttl}") Duration accessTtl,
      @Value("${authplatform.jwt.signing-keys:}") String configuredKeys,
      @Value("${authplatform.jwt.active-kid:authplatform-dev}") String activeKid,
      @Value("${spring.profiles.active:dev}") String profile,
      @Value("${authplatform.jwt.development-key-file}") String developmentKeyFile) {
    this.issuer = issuer;
    this.accessTtl = accessTtl;
    this.activeKid = activeKid;
    this.keys = loadKeys(configuredKeys, activeKid, profile, Path.of(developmentKeyFile));
  }

  public String issue(
      UUID subject,
      UUID audience,
      UUID sessionId,
      String role,
      List<String> roles,
      List<String> permissions) {
    return issue(subject, audience, sessionId, role, roles, permissions, accessTtl);
  }

  public String issue(
      UUID subject,
      UUID audience,
      UUID sessionId,
      String role,
      List<String> roles,
      List<String> permissions,
      Duration tokenTtl) {
    return issueForAudience(
        subject,
        sessionId,
        role,
        audience == null ? "authplatform-console" : audience.toString(),
        roles,
        permissions,
        tokenTtl);
  }

  public String issueForAudience(UUID subject, UUID sessionId, String role, String audience) {
    return issueForAudience(subject, sessionId, role, audience, null, null, accessTtl);
  }

  public String issueForAudience(
      UUID subject, UUID sessionId, String role, String audience, Duration tokenTtl) {
    return issueForAudience(subject, sessionId, role, audience, null, null, tokenTtl);
  }

  private String issueForAudience(
      UUID subject,
      UUID sessionId,
      String role,
      String audience,
      List<String> roles,
      List<String> permissions,
      Duration tokenTtl) {
    if (tokenTtl == null || tokenTtl.isZero() || tokenTtl.isNegative()) {
      throw new IllegalArgumentException("Access-token lifetime must be positive");
    }
    try {
      Date now = new Date();
      JWTClaimsSet.Builder claims =
          new JWTClaimsSet.Builder()
              .issuer(issuer)
              .subject(subject.toString())
              .audience(List.of(audience))
              .jwtID(UUID.randomUUID().toString())
              .issueTime(now)
              .expirationTime(new Date(now.getTime() + tokenTtl.toMillis()))
              .claim("sid", sessionId.toString());
      if (role != null) claims.claim("role", role);
      if (roles != null) claims.claim("roles", roles);
      if (permissions != null) claims.claim("permissions", permissions);
      SignedJWT jwt =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.RS256)
                  .keyID(activeKid)
                  .type(com.nimbusds.jose.JOSEObjectType.JWT)
                  .build(),
              claims.build());
      jwt.sign(new RSASSASigner(keys.get(activeKid).toPrivateKey()));
      return jwt.serialize();
    } catch (JOSEException ex) {
      throw new IllegalStateException("Unable to sign access token", ex);
    }
  }

  public JWTClaimsSet parse(String token, String expectedAudience) {
    try {
      SignedJWT jwt = SignedJWT.parse(token);
      if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())
          || !com.nimbusds.jose.JOSEObjectType.JWT.equals(jwt.getHeader().getType())
          || jwt.getHeader().getKeyID() == null) throw new ApiException(ErrorCode.UNAUTHENTICATED);
      RSAKey key = keys.get(jwt.getHeader().getKeyID());
      if (key == null || !jwt.verify(new RSASSAVerifier(key.toRSAPublicKey())))
        throw new ApiException(ErrorCode.UNAUTHENTICATED);
      JWTClaimsSet claims = jwt.getJWTClaimsSet();
      Date now = new Date();
      if (!issuer.equals(claims.getIssuer())
          || claims.getAudience() == null
          || !claims.getAudience().contains(expectedAudience)
          || claims.getExpirationTime() == null
          || claims.getExpirationTime().before(new Date(now.getTime() - CLOCK_SKEW.toMillis()))
          || (claims.getNotBeforeTime() != null
              && claims.getNotBeforeTime().after(new Date(now.getTime() + CLOCK_SKEW.toMillis())))
          || (claims.getIssueTime() != null
              && claims.getIssueTime().after(new Date(now.getTime() + CLOCK_SKEW.toMillis()))))
        throw new ApiException(ErrorCode.UNAUTHENTICATED);
      return claims;
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException(ErrorCode.UNAUTHENTICATED);
    }
  }

  public JWKSet jwks() {
    List<JWK> publicKeys = keys.values().stream().map(key -> (JWK) key.toPublicJWK()).toList();
    return new JWKSet(publicKeys);
  }

  public Duration accessTtl() {
    return accessTtl;
  }

  private static Map<String, RSAKey> loadKeys(
      String configured, String active, String profile, Path developmentKeyFile) {
    if (configured == null || configured.isBlank()) {
      if ("prod".equals(profile))
        throw new IllegalStateException("JWT_SIGNING_KEYS is required in the prod profile");
      configured = loadOrCreateDevelopmentKey(active, developmentKeyFile);
    }
    Map<String, RSAKey> loaded = new LinkedHashMap<>();
    try {
      for (String item : configured.split(";")) {
        String[] parts = item.trim().split("\\|", -1);
        if (parts.length != 3 || parts[0].isBlank()) throw new IllegalArgumentException();
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey =
            (RSAPrivateKey)
                factory.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(parts[1])));
        RSAPublicKey publicKey =
            (RSAPublicKey)
                factory.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(parts[2])));
        loaded.put(
            parts[0], new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(parts[0]).build());
      }
      if (!loaded.containsKey(active))
        throw new IllegalArgumentException("Active JWT kid is absent");
      return Map.copyOf(loaded);
    } catch (Exception ex) {
      throw new IllegalStateException(
          "JWT_SIGNING_KEYS must contain kid|base64-private|base64-public entries", ex);
    }
  }

  private static String loadOrCreateDevelopmentKey(String kid, Path keyFile) {
    try {
      Path absolutePath = keyFile.toAbsolutePath().normalize();
      Path directory = absolutePath.getParent();
      if (directory == null) throw new IOException("Development key file has no parent directory");
      Files.createDirectories(directory);

      try (FileChannel channel =
              FileChannel.open(
                  absolutePath,
                  StandardOpenOption.CREATE,
                  StandardOpenOption.READ,
                  StandardOpenOption.WRITE,
                  LinkOption.NOFOLLOW_LINKS);
          FileLock ignored = channel.lock()) {
        setOwnerOnly(
            absolutePath, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        if (channel.size() == 0) {
          ByteBuffer generated =
              StandardCharsets.UTF_8.encode(generateDevelopmentKey(kid) + System.lineSeparator());
          channel.position(0);
          while (generated.hasRemaining()) channel.write(generated);
          channel.force(true);
        }
        if (channel.size() > 16_384) throw new IOException("Development key file is too large");
        ByteBuffer contents = ByteBuffer.allocate((int) channel.size());
        channel.position(0);
        while (contents.hasRemaining() && channel.read(contents) >= 0) {}
        contents.flip();
        String configured = StandardCharsets.UTF_8.decode(contents).toString().trim();
        if (configured.isEmpty()) throw new IOException("Development key file is empty");
        return configured;
      }
    } catch (IOException | java.nio.channels.OverlappingFileLockException ex) {
      throw new IllegalStateException(
          "Unable to load the persistent development JWT key from " + keyFile, ex);
    }
  }

  private static void setOwnerOnly(Path path, Set<PosixFilePermission> permissions)
      throws IOException {
    try {
      Files.setPosixFilePermissions(path, permissions);
    } catch (UnsupportedOperationException ex) {
      // Non-POSIX filesystems use their native account permissions.
    }
  }

  private static String generateDevelopmentKey(String kid) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      KeyPair pair = generator.generateKeyPair();
      return kid
          + "|"
          + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded())
          + "|"
          + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    } catch (Exception ex) {
      throw new IllegalStateException("Unable to create development signing key", ex);
    }
  }
}
