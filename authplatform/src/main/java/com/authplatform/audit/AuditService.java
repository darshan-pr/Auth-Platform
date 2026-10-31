package com.authplatform.audit;

import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
public class AuditService {
  private static final Logger log = LoggerFactory.getLogger(AuditService.class);
  private final AuditLogRepository repository;
  private final boolean readAuditingEnabled;

  public AuditService(
      AuditLogRepository repository,
      @Value("${authplatform.audit.reads-enabled:false}") boolean readAuditingEnabled) {
    this.repository = repository;
    this.readAuditingEnabled = readAuditingEnabled;
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void recordAccount(String action, UUID accountId, String ipAddress) {
    save(action, "ACCOUNT", accountId, null, null, ipAddress, null);
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void recordAppUser(String action, UUID appUserId, UUID appId, String ipAddress) {
    save(action, "APP_USER", null, appUserId, appId, ipAddress, null);
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void recordAppChange(String action, UUID accountId, UUID appId) {
    save(action, "ACCOUNT", accountId, null, appId, null, null);
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void recordAppChange(
      String action, UUID accountId, UUID appId, Map<String, Object> metadata) {
    save(action, "ACCOUNT", accountId, null, appId, null, metadata);
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void recordSa(
      String action, UUID saAccountId, UUID appId, String ipAddress, Map<String, Object> metadata) {
    if (!readAuditingEnabled && action.startsWith("SA_VIEW_")) return;
    save(action, "SA", saAccountId, null, appId, ipAddress, metadata);
  }

  private void save(
      String action,
      String actorType,
      UUID accountId,
      UUID appUserId,
      UUID appId,
      String ipAddress,
      Map<String, Object> metadata) {
    String requestId = MDC.get("requestId");
    HttpServletRequest request =
        RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
            ? attributes.getRequest()
            : null;
    String source = ipAddress != null || request == null ? ipAddress : request.getRemoteAddr();
    repository.save(
        AuditLog.create(
            action,
            actorType,
            accountId,
            appUserId,
            appId,
            source,
            requestId,
            details(request, metadata)));
    log.info(
        "audit action={} actorType={} subject={} appId={} ip={}",
        action,
        actorType,
        accountId == null ? appUserId : accountId,
        appId,
        ipAddress);
  }

  // Without this, most events (logins, refreshes, verifications) were stored with empty details.
  private static Map<String, Object> details(
      HttpServletRequest request, Map<String, Object> metadata) {
    Map<String, Object> details = new LinkedHashMap<>();
    if (request != null) {
      details.put("method", request.getMethod());
      details.put("path", request.getRequestURI());
      String userAgent = request.getHeader("User-Agent");
      if (userAgent != null && !userAgent.isBlank()) {
        details.put("userAgent", userAgent.length() > 255 ? userAgent.substring(0, 255) : userAgent);
      }
    }
    if (metadata != null) details.putAll(metadata);
    return details.isEmpty() ? null : details;
  }
}
