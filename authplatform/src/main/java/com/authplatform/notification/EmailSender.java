package com.authplatform.notification;

public interface EmailSender {
  void send(String to, String subject, String link);

  default void sendText(String to, String subject, String message) {
    send(to, subject, message);
  }
}
