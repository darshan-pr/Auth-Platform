package com.authplatform.audit;

import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

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
    repository.save(
        AuditLog.create(
            action, actorType, accountId, appUserId, appId, ipAddress, requestId, metadata));
    log.info(
        "audit action={} actorType={} subject={} appId={} ip={}",
        action,
        actorType,
        accountId == null ? appUserId : accountId,
        appId,
        ipAddress);
  }
}
