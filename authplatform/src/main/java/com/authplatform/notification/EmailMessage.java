package com.authplatform.notification;

public record EmailMessage(
    String to, String fromName, String subject, String textBody, String htmlBody, String iconUrl) {

  public static EmailMessage plainText(String to, String subject, String body) {
    return new EmailMessage(to, "Auth Platform", subject, body, null, null);
  }
}
