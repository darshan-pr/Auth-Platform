package com.authplatform.auth.service;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.stereotype.Component;

@Component
public class SessionRevocationCacheInitializer implements SmartInitializingSingleton {
  private final SessionService sessions;

  public SessionRevocationCacheInitializer(SessionService sessions) {
    this.sessions = sessions;
  }

  @Override
  public void afterSingletonsInstantiated() {
    sessions.restoreRevocationCache();
  }
}
