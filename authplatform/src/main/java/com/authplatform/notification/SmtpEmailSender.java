package com.authplatform.notification;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
public class SmtpEmailSender implements EmailSender {
  private static final Logger log = LoggerFactory.getLogger(SmtpEmailSender.class);
  private final JavaMailSender sender;
  private final String from;

  public SmtpEmailSender(
      JavaMailSender sender, @Value("${SMTP_FROM:${SMTP_USERNAME:}}") String from) {
    this.sender = sender;
    this.from = from;
  }

  @Async
  public void send(String to, String subject, String link) {
    sendMessage(to, subject, "Use this link to continue: " + link);
  }

  @Async
  public void sendText(String to, String subject, String messageText) {
    sendMessage(to, subject, messageText);
  }

  private void sendMessage(String to, String subject, String body) {
    try {
      MimeMessage message = sender.createMimeMessage();
      if (!from.isBlank()) message.setFrom(from);
      message.setRecipients(MimeMessage.RecipientType.TO, to);
      message.setSubject(subject);
      message.setText(body);
      sender.send(message);
    } catch (MessagingException ex) {
      log.warn(
          "Unable to send auth email subject={} recipientDomain={}",
          subject,
          to.substring(to.indexOf('@') + 1));
    }
  }
}
