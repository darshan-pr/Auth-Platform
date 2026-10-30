package com.authplatform.common.security;

import java.util.UUID;

public record AuthenticatedPrincipal(
    UUID subjectId, UUID appId, String sessionId, boolean appUser) {}
