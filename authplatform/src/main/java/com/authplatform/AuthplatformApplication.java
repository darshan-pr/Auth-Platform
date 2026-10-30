package com.authplatform;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class AuthplatformApplication {
  public static void main(String[] args) {
    SpringApplication.run(AuthplatformApplication.class, args);
  }
}
