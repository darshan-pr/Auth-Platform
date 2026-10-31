package com.authplatform.app.service;

import java.security.SecureRandom;

/** Random passwords for invited users, using characters that survive copy/paste from email. */
public final class TemporaryPassword {
  private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  private static final String LOWER = "abcdefghijkmnopqrstuvwxyz";
  private static final String DIGITS = "23456789";
  private static final String ALL = UPPER + LOWER + DIGITS;
  private static final int LENGTH = 14;
  private static final SecureRandom RANDOM = new SecureRandom();

  private TemporaryPassword() {}

  public static String generate() {
    char[] password = new char[LENGTH];
    password[0] = pick(UPPER);
    password[1] = pick(LOWER);
    password[2] = pick(DIGITS);
    for (int i = 3; i < LENGTH; i++) password[i] = pick(ALL);
    for (int i = LENGTH - 1; i > 0; i--) {
      int j = RANDOM.nextInt(i + 1);
      char swap = password[i];
      password[i] = password[j];
      password[j] = swap;
    }
    return new String(password);
  }

  private static char pick(String characters) {
    return characters.charAt(RANDOM.nextInt(characters.length()));
  }
}
