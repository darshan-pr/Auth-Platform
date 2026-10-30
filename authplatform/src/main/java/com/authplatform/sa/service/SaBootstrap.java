package com.authplatform.sa.service;

import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.user.entity.Account;
import com.authplatform.user.entity.PlatformRole;
import com.authplatform.user.repository.AccountRepository;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class SaBootstrap implements ApplicationRunner {
  private static final Logger log = LoggerFactory.getLogger(SaBootstrap.class);

  private final AccountRepository accounts;
  private final PasswordHasher passwords;
  private final boolean enabled;
  private final String email;
  private final String name;
  private final String password;

  public SaBootstrap(
      AccountRepository accounts,
      PasswordHasher passwords,
      @Value("${authplatform.sa.bootstrap.enabled:false}") boolean enabled,
      @Value("${authplatform.sa.bootstrap.email:}") String email,
      @Value("${authplatform.sa.bootstrap.name:Platform SA}") String name,
      @Value("${authplatform.sa.bootstrap.password:}") String password) {
    this.accounts = accounts;
    this.passwords = passwords;
    this.enabled = enabled;
    this.email = email;
    this.name = name;
    this.password = password;
  }

  @Override
  public void run(ApplicationArguments args) {
    if (!enabled) return;
    if (accounts.countByPlatformRole(PlatformRole.SA) > 0) {
      log.info("SA bootstrap skipped because an SA account already exists");
      return;
    }
    if (email.isBlank() || password.isBlank()) {
      throw new IllegalStateException(
          "SA bootstrap is enabled but SA_BOOTSTRAP_EMAIL or SA_BOOTSTRAP_PASSWORD is blank");
    }
    String normalized = email.trim().toLowerCase(Locale.ROOT);
    if (accounts.existsByEmailIgnoreCase(normalized)) {
      throw new IllegalStateException(
          "SA bootstrap email already belongs to an account; choose another email");
    }
    Account account =
        accounts.save(Account.registerSa(normalized, passwords.hash(password), name.trim()));
    log.info("Created initial SA account id={} email={}", account.getId(), account.getEmail());
  }
}
