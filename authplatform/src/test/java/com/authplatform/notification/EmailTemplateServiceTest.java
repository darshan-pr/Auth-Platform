package com.authplatform.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authplatform.app.entity.App;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class EmailTemplateServiceTest {
  private final EmailTemplateService templates =
      new EmailTemplateService("https://api.authplatform.example");

  @Test
  void appEmailsUseAppSenderNameAndReferenceUploadedIconByUrl() {
    App app = mock(App.class);
    when(app.getName()).thenReturn("Northstar");
    when(app.getId()).thenReturn(UUID.fromString("95f59855-df58-4e31-9ec8-51f9814187a6"));
    when(app.getIconData()).thenReturn(new byte[] {1, 2, 3});
    when(app.getIconContentType()).thenReturn("image/png");

    EmailMessage message =
        templates.emailVerification(
            app, "user@example.com", "Ada", "https://northstar.example/verify?token=secret");

    assertThat(message.fromName()).isEqualTo("Northstar");
    assertThat(message.subject()).isEqualTo("Verify your email - Northstar");
    assertThat(message.iconUrl())
        .isEqualTo(
            "https://api.authplatform.example/api/public/app-icons/95f59855-df58-4e31-9ec8-51f9814187a6");
    assertThat(message.htmlBody()).contains(message.iconUrl(), "width=\"32\"", "Verify email");
    assertThat(message.htmlBody()).doesNotContain("cid:");
    assertThat(message.textBody()).contains("https://northstar.example/verify?token=secret");
  }

  @Test
  void loginAlertEscapesDynamicContentAndIncludesSignInContext() {
    App app = mock(App.class);
    when(app.getName()).thenReturn("Northstar");

    EmailMessage message =
        templates.loginDetected(
            app,
            "user@example.com",
            "<script>alert(1)</script>",
            "203.0.113.8",
            "Browser <script>",
            Instant.parse("2026-10-30T12:00:00Z"));

    assertThat(message.htmlBody())
        .contains("&lt;script&gt;alert(1)&lt;/script&gt;", "203.0.113.8", "Browser &lt;script&gt;");
    assertThat(message.htmlBody()).doesNotContain("<script>");
    assertThat(message.textBody()).contains("New sign-in detected", "203.0.113.8");
  }

  @Test
  void passwordResetOtpUsesTheSharedCodeLayout() {
    EmailMessage message =
        templates.oneTimeCode(null, "user@example.com", "Ada", "123456", true);

    assertThat(message.subject()).isEqualTo("Your password reset code - Auth Platform");
    assertThat(message.htmlBody())
        .contains(
            "123456",
            "expires in 5 minutes",
            "https://api.authplatform.example/api/public/email-assets/platform-icon",
            "#1769aa");
    assertThat(message.htmlBody()).doesNotContain("cid:");
    assertThat(message.textBody()).contains("Your one-time password is 123456.");
    assertThat(message.textBody()).contains("Hello Ada,");
    assertThat(message.textBody().indexOf("Your one-time password is")).isGreaterThan(200);
    int previewStart = message.htmlBody().indexOf("display:none");
    int previewEnd = message.htmlBody().indexOf("</div>", previewStart);
    assertThat(message.htmlBody().substring(previewStart, previewEnd)).doesNotContain("123456");
  }
}
