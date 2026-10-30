package com.authplatform.role.repository;

import com.authplatform.role.entity.Role;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, UUID> {
  Role save(Role role);

  Optional<Role> findByAppIdAndDefaultRoleTrue(UUID appId);

  List<Role> findAllByAppId(UUID appId);

  Optional<Role> findByIdAndAppId(UUID id, UUID appId);
}
