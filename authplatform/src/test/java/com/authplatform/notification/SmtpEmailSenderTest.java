package com.authplatform.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.mail.Session;
import jakarta.mail.Multipart;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSender;

class SmtpEmailSenderTest {
  @Test
  void sendsHtmlWithAppNameAndConfiguredSenderAddress() throws Exception {
    JavaMailSender javaMailSender = mock(JavaMailSender.class);
    MimeMessage mimeMessage =
        new MimeMessage(Session.getInstance(new Properties()));
    when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
    SmtpEmailSender sender = new SmtpEmailSender(javaMailSender, "noreply@example.com");
    EmailMessage email =
        new EmailMessage(
            "user@example.com",
            "Northstar",
            "Verify your email - Northstar",
            "Verify your email",
            "<html><body><img src=\"https://api.example.com/api/public/app-icons/123\">Verify your email</body></html>",
            "https://api.example.com/api/public/app-icons/123");

    sender.send(email);

    verify(javaMailSender).send(mimeMessage);
    InternetAddress from = (InternetAddress) mimeMessage.getFrom()[0];
    assertThat(from.getAddress()).isEqualTo("noreply@example.com");
    assertThat(from.getPersonal()).isEqualTo("Northstar");
    assertThat(mimeMessage.getSubject()).isEqualTo("Verify your email - Northstar");
    assertThat(mimeMessage.getContent()).isInstanceOf(Multipart.class);
    ByteArrayOutputStream rawMessage = new ByteArrayOutputStream();
    mimeMessage.writeTo(rawMessage);
    String serialized = rawMessage.toString(StandardCharsets.UTF_8);
    assertThat(serialized)
        .contains("https://api.example.com/api/public/app-icons/123")
        .doesNotContain("Content-ID:", "Content-Disposition: attachment", "filename=");
  }
}
