package com.authplatform.notification;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.InternetAddress;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
public class SmtpEmailSender implements EmailSender {
  private static final Logger log = LoggerFactory.getLogger(SmtpEmailSender.class);
  private static final int MAX_ATTEMPTS = 3;
  private static final long RETRY_DELAY_MS = 750;
  private final JavaMailSender sender;
  private final String from;

  public SmtpEmailSender(
      JavaMailSender sender, @Value("${SMTP_FROM:${SMTP_USERNAME:}}") String from) {
    this.sender = sender;
    this.from = from;
  }

  @Async(EmailExecutorConfig.EXECUTOR)
  public void send(String to, String subject, String body) {
    sendMessage(EmailMessage.plainText(to, subject, body));
  }

  @Async(EmailExecutorConfig.EXECUTOR)
  public void send(EmailMessage email) {
    sendMessage(email);
  }

  @Async(EmailExecutorConfig.EXECUTOR)
  public void sendText(String to, String subject, String messageText) {
    sendMessage(EmailMessage.plainText(to, subject, messageText));
  }

  private void sendMessage(EmailMessage email) {
    long started = System.nanoTime();
    try {
      MimeMessage message = sender.createMimeMessage();
      MimeMessageHelper helper =
          new MimeMessageHelper(
              message,
              email.htmlBody() != null
                  ? MimeMessageHelper.MULTIPART_MODE_MIXED
                  : MimeMessageHelper.MULTIPART_MODE_NO,
              StandardCharsets.UTF_8.name());
      if (!from.isBlank()) {
        InternetAddress[] addresses = InternetAddress.parse(from, true);
        if (addresses.length != 1) throw new MessagingException("SMTP_FROM must be one address");
        addresses[0].setPersonal(safeHeader(email.fromName()), StandardCharsets.UTF_8.name());
        helper.setFrom(addresses[0]);
      }
      helper.setTo(email.to());
      helper.setSubject(safeHeader(email.subject()));
      if (email.htmlBody() == null) {
        helper.setText(email.textBody());
      } else {
        helper.setText(email.textBody(), email.htmlBody());
      }
      deliver(message, email);
      log.info(
          "Sent auth email subject={} recipientDomain={} elapsedMs={}",
          email.subject(),
          recipientDomain(email.to()),
          (System.nanoTime() - started) / 1_000_000);
    } catch (MessagingException | UnsupportedEncodingException ex) {
      log.error(
          "Unable to send auth email subject={} recipientDomain={}",
          email.subject(),
          recipientDomain(email.to()),
          ex);
      throw new IllegalStateException("Unable to send auth email", ex);
    }
  }

  // Gmail intermittently answers with transient 4xx errors or stalls a connection; retry those
  // instead of silently dropping a one-time code.
  private void deliver(MimeMessage message, EmailMessage email) {
    for (int attempt = 1; ; attempt++) {
      try {
        sender.send(message);
        return;
      } catch (MailSendException ex) {
        if (attempt >= MAX_ATTEMPTS) throw ex;
        log.warn(
            "Auth email attempt {} failed subject={} recipientDomain={}: {}",
            attempt,
            email.subject(),
            recipientDomain(email.to()),
            ex.getMessage());
        try {
          Thread.sleep(RETRY_DELAY_MS * attempt);
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
          throw ex;
        }
      }
    }
  }

  private static String safeHeader(String value) {
    return value == null ? "" : value.replaceAll("[\\r\\n\\t\\p{Cntrl}]", " ").trim();
  }

  private static String recipientDomain(String to) {
    if (to == null) return "unknown";
    int separator = to.lastIndexOf('@');
    return separator < 0 ? "unknown" : to.substring(separator + 1);
  }
}
