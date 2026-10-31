package com.authplatform.notification;

public interface EmailSender {
  void send(String to, String subject, String body);

  default void send(EmailMessage message) {
    send(message.to(), message.subject(), message.textBody());
  }

  default void sendText(String to, String subject, String message) {
    send(to, subject, message);
  }
}
