package com.authplatform.role.entity;

import com.authplatform.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "roles")
public class Role extends BaseEntity {
  @Column(name = "app_id", nullable = false)
  private UUID appId;

  @Column(nullable = false)
  private String name;

  @Column(name = "display_name", length = 120)
  private String displayName;

  private String description;

  @Column(name = "is_default", nullable = false)
  private boolean defaultRole;

  @Column(nullable = false)
  private boolean enabled = true;

  protected Role() {}

  public static Role defaultFor(UUID appId) {
    Role r = new Role();
    r.appId = appId;
    r.name = "user";
    r.displayName = "User";
    r.defaultRole = true;
    r.description = "Default user role";
    return r;
  }

  public static Role create(
      UUID appId, String name, String displayName, String description) {
    Role role = new Role();
    role.appId = appId;
    role.name = name;
    role.displayName = displayName;
    role.description = description;
    return role;
  }

  public void update(String name, String displayName, String description, Boolean enabled) {
    if (name != null) this.name = name;
    if (displayName != null) this.displayName = displayName;
    if (description != null) this.description = description;
    if (enabled != null) this.enabled = enabled;
  }

  public void setDefaultRole(boolean defaultRole) {
    this.defaultRole = defaultRole;
  }

  public UUID getAppId() {
    return appId;
  }

  public String getName() {
    return name;
  }

  public String getDisplayName() {
    return displayName;
  }

  public String getDescription() {
    return description;
  }

  public boolean isDefaultRole() {
    return defaultRole;
  }

  public boolean isEnabled() {
    return enabled;
  }
}
