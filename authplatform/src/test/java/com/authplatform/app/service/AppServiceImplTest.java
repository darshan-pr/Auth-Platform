package com.authplatform.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authplatform.app.dto.AppDtos;
import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.app.service.impl.AppServiceImpl;
import com.authplatform.audit.AuditService;
import com.authplatform.auth.service.SessionService;
import com.authplatform.common.crypto.PasswordHasher;
import com.authplatform.common.crypto.SecureTokenGenerator;
import com.authplatform.common.crypto.TokenHasher;
import com.authplatform.common.exception.ApiException;
import com.authplatform.role.service.RoleService;
import com.authplatform.user.entity.AppUser;
import com.authplatform.user.repository.AppUserRepository;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

class AppServiceImplTest {
  @Test
  void listUsersMapsRepositoryEntitiesToPublicViews() {
    UUID ownerId = UUID.randomUUID();
    UUID appId = UUID.randomUUID();
    AppRepository apps = mock(AppRepository.class);
    AppUserRepository users = mock(AppUserRepository.class);
    when(apps.findByIdAndOwnerAccountId(appId, ownerId)).thenReturn(Optional.of(mock(App.class)));

    AppUser user = AppUser.register(appId, "alice@example.com", "hashed-password", "Alice");
    when(users.findAllByAppId(eq(appId), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(user)));

    AppServiceImpl service =
        new AppServiceImpl(
            apps,
            mock(RoleService.class),
            mock(SecureTokenGenerator.class),
            mock(TokenHasher.class),
            mock(AuditService.class),
            users,
            mock(PasswordHasher.class),
            mock(SessionService.class),
            10,
            10);

    var result = service.listUsers(ownerId, appId, 0, 50);

    assertThat(result)
        .singleElement()
        .satisfies(
            view -> {
              assertThat(view.appId()).isEqualTo(appId);
              assertThat(view.name()).isEqualTo("Alice");
              assertThat(view.email()).isEqualTo("alice@example.com");
              assertThat(view.status()).isEqualTo("ACTIVE");
            });
  }

  @Test
  void updatePersistsAndReturnsUploadedIconData() {
    UUID ownerId = UUID.randomUUID();
    App app =
        App.create(
            ownerId,
            "Demo",
            List.of(),
            "pk_demo",
            "hashed-secret",
            "hint",
            null,
            null);
    AppRepository apps = mock(AppRepository.class);
    RoleService roles = mock(RoleService.class);
    when(apps.findByIdAndOwnerAccountId(app.getId(), ownerId)).thenReturn(Optional.of(app));
    when(roles.findDefault(app.getId()))
        .thenReturn(new AppDtos.RoleSummary(UUID.randomUUID(), "member"));
    byte[] pngSignature = {
      (byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
    };
    String icon = "data:image/png;base64," + Base64.getEncoder().encodeToString(pngSignature);

    AppDtos.AppResponse result =
        service(apps, roles)
            .update(ownerId, app.getId(), updateRequest(null, icon));

    assertThat(result.iconUrl()).isNull();
    assertThat(result.iconDataUrl()).isEqualTo(icon);
    assertThat(result.iconPositionX()).isEqualTo(50);
    assertThat(result.iconZoomPercent()).isEqualTo(100);
  }

  @Test
  void updateRejectsInvalidImageDataAndInsecureUrls() {
    UUID ownerId = UUID.randomUUID();
    App app =
        App.create(
            ownerId,
            "Demo",
            List.of(),
            "pk_demo",
            "hashed-secret",
            "hint",
            null,
            null);
    AppRepository apps = mock(AppRepository.class);
    RoleService roles = mock(RoleService.class);
    when(apps.findByIdAndOwnerAccountId(app.getId(), ownerId)).thenReturn(Optional.of(app));

    assertThatThrownBy(
            () ->
                service(apps, roles)
                    .update(
                        ownerId,
                        app.getId(),
                        updateRequest(null, "data:image/png;base64,ZmFrZQ==")))
        .isInstanceOf(ApiException.class);
    assertThatThrownBy(
            () ->
                service(apps, roles)
                    .update(
                        ownerId,
                        app.getId(),
                        updateRequest("http://images.example.com/icon.png", null)))
        .isInstanceOf(ApiException.class);
  }

  private AppServiceImpl service(AppRepository apps, RoleService roles) {
    return new AppServiceImpl(
        apps,
        roles,
        mock(SecureTokenGenerator.class),
        mock(TokenHasher.class),
        mock(AuditService.class),
        mock(AppUserRepository.class),
        mock(PasswordHasher.class),
        mock(SessionService.class),
        10,
        10);
  }

  private AppDtos.UpdateAppRequest updateRequest(String iconUrl, String iconDataUrl) {
    return new AppDtos.UpdateAppRequest(
        null, null, null, null, null, null, null, null, null, true,
        iconUrl, iconDataUrl, 50, 50, 100);
  }
}
