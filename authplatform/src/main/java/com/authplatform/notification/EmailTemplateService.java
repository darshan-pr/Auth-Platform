package com.authplatform.notification;

import com.authplatform.app.entity.App;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EmailTemplateService {
  private static final String PLATFORM_NAME = "Auth Platform";
  private static final DateTimeFormatter TIMESTAMP_FORMAT =
      DateTimeFormatter.ofPattern("MMM d, yyyy 'at' h:mm a 'UTC'").withZone(ZoneOffset.UTC);
  private final String publicBaseUrl;

  public EmailTemplateService(
      @Value("${authplatform.email.public-base-url:}") String publicBaseUrl) {
    this.publicBaseUrl = normalizePublicBaseUrl(publicBaseUrl);
  }

  public EmailMessage emailVerification(App app, String to, String name, String link) {
    return render(
        app,
        to,
        "Verify your email",
        "Confirm your email",
        "Confirm your email address to finish setting up your account.",
        name,
        null,
        List.of(),
        "Verify email",
        link,
        "If you did not create an account, you can ignore this message.");
  }

  public EmailMessage welcome(App app, String to, String name) {
    return render(
        app,
        to,
        "Welcome",
        "Your account is ready",
        "Your email has been verified and your account is ready to use.",
        name,
        null,
        List.of(),
        null,
        null,
        "You can now sign in to your account.");
  }

  public EmailMessage passwordReset(App app, String to, String name, String link) {
    return render(
        app,
        to,
        "Reset your password",
        "Reset your password",
        "We received a request to reset the password for your account.",
        name,
        null,
        List.of(),
        "Reset password",
        link,
        "If you did not request a password reset, ignore this message. Your password will not change.");
  }

  public EmailMessage oneTimeCode(
      App app, String to, String name, String code, boolean passwordReset) {
    String purpose = passwordReset ? "password reset" : "sign-in";
    return render(
        app,
        to,
        passwordReset ? "Your password reset code" : "Your sign-in code",
        passwordReset ? "Reset your password" : "Confirm your sign-in",
        passwordReset
            ? "Use this one-time code to reset your password."
            : "Use this one-time code to finish signing in.",
        name,
        code,
        List.of(),
        null,
        null,
        "Never share this code with anyone. If you did not request a " + purpose + ", ignore this message.");
  }

  public EmailMessage passwordChanged(App app, String to, String name) {
    return render(
        app,
        to,
        "Your password was changed",
        "Password changed",
        "The password for your account was changed successfully.",
        name,
        null,
        List.of(),
        null,
        null,
        "If you did not make this change, reset your password and contact the application administrator.");
  }

  public EmailMessage loginDetected(
      App app, String to, String name, String ip, String userAgent, Instant occurredAt) {
    List<Detail> details = new ArrayList<>();
    details.add(new Detail("Time", TIMESTAMP_FORMAT.format(occurredAt)));
    if (ip != null && !ip.isBlank()) details.add(new Detail("IP address", ip));
    if (userAgent != null && !userAgent.isBlank()) {
      details.add(new Detail("Device", truncate(userAgent, 240)));
    }
    return render(
        app,
        to,
        "New sign-in detected",
        "New sign-in detected",
        "A successful sign-in was detected for your account.",
        name,
        null,
        details,
        null,
        null,
        "If this was not you, reset your password and review your active sessions.");
  }

  public EmailMessage temporaryLock(
      App app, String to, String name, Duration lockDuration) {
    long minutes = Math.max(1, lockDuration.toMinutes());
    return render(
        app,
        to,
        "Sign-in temporarily paused",
        "Sign-in temporarily paused",
        "We temporarily paused sign-ins after too many unsuccessful attempts.",
        name,
        null,
        List.of(new Detail("Try again", "In about " + minutes + " minutes")),
        null,
        null,
        "If these attempts were not yours, reset your password before signing in again.");
  }

  public EmailMessage accountStatusChanged(
      App app, String to, String name, String status) {
    String displayStatus = status == null ? "updated" : status.toLowerCase().replace('_', ' ');
    return render(
        app,
        to,
        "Account status updated",
        "Account status updated",
        "The status of your account has been changed.",
        name,
        null,
        List.of(new Detail("Status", displayStatus)),
        null,
        null,
        "If you have questions about this change, contact the application administrator.");
  }

  private EmailMessage render(
      App app,
      String to,
      String subject,
      String heading,
      String intro,
      String name,
      String code,
      List<Detail> details,
      String actionLabel,
      String actionUrl,
      String note) {
    Brand brand = brand(app);
    String greeting = name == null || name.isBlank() ? "Hello," : "Hello " + clean(name) + ",";
    String preheader = heading + ". " + intro;
    StringBuilder text =
        new StringBuilder(greeting)
            .append("\n\n")
            .append(heading)
            .append("\n\n")
            .append(intro);
    if (code != null) {
      if (note != null && !note.isBlank()) {
        text.append("\n\n")
            .append(note)
            .append("\n\nOpen this email to view the one-time code.");
      }
      text.append("\n\nYour one-time password is ")
          .append(code)
          .append(". It expires in 5 minutes.");
    }
    for (Detail detail : details) {
      text.append("\n").append(detail.label()).append(": ").append(detail.value());
    }
    if (actionUrl != null) {
      text.append("\n\n").append(actionLabel).append(":\n").append(actionUrl);
    }
    if (code == null && note != null && !note.isBlank()) text.append("\n\n").append(note);
    text.append("\n\n").append(brand.name());

    String icon = brand.iconUrl() == null ? null : escapeHtml(brand.iconUrl());
    StringBuilder html = new StringBuilder();
    html.append("<!doctype html><html lang=\"en\"><body style=\"margin:0;background:#f4f6fa;color:#172033;font-family:Arial,Helvetica,sans-serif\">");
    html.append("<div style=\"display:none;max-height:0;overflow:hidden;opacity:0\">")
        .append(escapeHtml(preheader))
        .append("</div>");
    html.append("<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"background:#f4f6fa;padding:32px 12px\"><tr><td align=\"center\">");
    html.append("<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"max-width:560px\"><tr><td style=\"padding:8px 0 20px;text-align:center\">");
    if (icon != null) {
      html.append("<img src=\"")
          .append(icon)
          .append("\" width=\"32\" height=\"32\" alt=\"\" style=\"display:inline-block;width:32px;height:32px;max-width:32px;max-height:32px;border-radius:8px;object-fit:cover;vertical-align:middle;margin-right:8px\">");
    }
    if (brand.platform()) {
      html.append("<span style=\"font-size:16px;font-weight:700;vertical-align:middle;color:#172033\">Auth</span><span style=\"font-size:16px;font-weight:700;vertical-align:middle;color:#1769aa\"> Platform</span>");
    } else {
      html.append("<span style=\"font-size:16px;font-weight:700;color:#172033;vertical-align:middle\">")
          .append(escapeHtml(brand.name()))
          .append("</span>");
    }
    html.append("</td></tr><tr><td style=\"background:#ffffff;border:1px solid #e4e8f0;border-radius:12px;padding:32px\">");
    html.append("<p style=\"margin:0 0 20px;color:#475467;font-size:15px;line-height:1.6\">")
        .append(escapeHtml(greeting))
        .append("</p><h1 style=\"margin:0 0 12px;font-size:23px;line-height:1.3;color:")
        .append(brand.accentColor())
        .append("\">")
        .append(escapeHtml(heading))
        .append("</h1><p style=\"margin:0 0 20px;color:#475467;font-size:15px;line-height:1.65\">")
        .append(escapeHtml(intro))
        .append("</p>");
    if (code != null) {
      html.append("<div style=\"margin:20px 0;padding:16px;background:#f5f7fb;border:1px solid #e4e8f0;border-radius:8px;text-align:center;font-family:Arial,Helvetica,sans-serif;font-size:30px;font-weight:700;letter-spacing:8px;color:#172033\">")
          .append(escapeHtml(code))
          .append("</div><p style=\"margin:0 0 20px;color:#667085;font-size:13px\">This code expires in 5 minutes.</p>");
    }
    if (!details.isEmpty()) {
      html.append("<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"margin:16px 0 20px;border-collapse:collapse\">");
      for (Detail detail : details) {
        html.append("<tr><td style=\"padding:8px 0;color:#667085;font-size:13px;vertical-align:top\">")
            .append(escapeHtml(detail.label()))
            .append("</td><td style=\"padding:8px 0;color:#172033;font-size:13px;text-align:right;vertical-align:top\">")
            .append(escapeHtml(detail.value()))
            .append("</td></tr>");
      }
      html.append("</table>");
    }
    if (actionUrl != null) {
      html.append("<p style=\"margin:24px 0;text-align:center\"><a href=\"")
          .append(escapeHtml(actionUrl))
          .append("\" style=\"display:inline-block;background:")
          .append(brand.accentColor())
          .append(";border-radius:7px;padding:12px 20px;color:#ffffff;font-size:14px;font-weight:700;text-decoration:none\">")
          .append(escapeHtml(actionLabel))
          .append("</a></p><p style=\"margin:0 0 20px;color:#667085;font-size:12px;line-height:1.6\">If the button does not work, copy this link into your browser:<br><a href=\"")
          .append(escapeHtml(actionUrl))
          .append("\" style=\"color:")
          .append(brand.accentColor())
          .append(";word-break:break-all\">")
          .append(escapeHtml(actionUrl))
          .append("</a></p>");
    }
    if (note != null && !note.isBlank()) {
      html.append("<p style=\"margin:20px 0 0;padding-top:16px;border-top:1px solid #eef0f4;color:#667085;font-size:13px;line-height:1.6\">")
          .append(escapeHtml(note))
          .append("</p>");
    }
    html.append("</td></tr><tr><td style=\"padding:18px 12px;text-align:center;color:#98a2b3;font-size:12px;line-height:1.5\">This is an automated security message from ")
        .append(escapeHtml(brand.name()))
        .append(".</td></tr></table></td></tr></table></body></html>");

    return new EmailMessage(
        to,
        brand.name(),
        subject + " - " + brand.name(),
        text.toString(),
        html.toString(),
        brand.iconUrl());
  }

  private Brand brand(App app) {
    if (app == null) {
      return new Brand(
          PLATFORM_NAME,
          publicAssetUrl("/api/public/email-assets/platform-icon"),
          true,
          "#1769aa");
    }
    String name = clean(app.getName());
    if (name.isBlank()) name = PLATFORM_NAME;
    String iconUrl = app.getIconUrl();
    if (iconUrl == null && app.getIconData() != null) {
      iconUrl = publicAssetUrl("/api/public/app-icons/" + app.getId());
    }
    return new Brand(name, iconUrl, false, "#315efb");
  }

  private String publicAssetUrl(String path) {
    return publicBaseUrl.isBlank() ? null : publicBaseUrl + path;
  }

  private static String normalizePublicBaseUrl(String value) {
    String baseUrl = value == null ? "" : value.trim();
    while (baseUrl.endsWith("/")) {
      baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
    }
    if (baseUrl.isBlank()) return "";

    URI uri = URI.create(baseUrl);
    String scheme = uri.getScheme();
    String host = uri.getHost();
    boolean https = "https".equalsIgnoreCase(scheme) && host != null;
    boolean localHttp =
        "http".equalsIgnoreCase(scheme)
            && List.of("localhost", "127.0.0.1", "::1", "[::1]").contains(host);
    if ((!https && !localHttp)
        || uri.getRawUserInfo() != null
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null) {
      throw new IllegalArgumentException(
          "AUTH_PLATFORM_PUBLIC_BASE_URL must be an HTTPS origin or a local development URL");
    }
    return baseUrl;
  }

  private static String clean(String value) {
    return value == null ? "" : value.replaceAll("[\\r\\n\\t\\p{Cntrl}]", " ").trim();
  }

  private static String truncate(String value, int maxLength) {
    String cleanValue = clean(value);
    return cleanValue.length() <= maxLength
        ? cleanValue
        : cleanValue.substring(0, maxLength) + "...";
  }

  private static String escapeHtml(String value) {
    return value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;");
  }

  private record Brand(String name, String iconUrl, boolean platform, String accentColor) {}

  private record Detail(String label, String value) {}
}
