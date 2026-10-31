package com.authplatform.app.service;

import com.authplatform.app.dto.AppDtos;
import java.util.List;
import java.util.UUID;

public interface AppService {
  AppDtos.AppCreatedResponse create(UUID owner, AppDtos.CreateAppRequest request);

  List<AppDtos.AppResponse> list(UUID owner, int page, int size);

  com.authplatform.common.dto.PageResult<AppDtos.AppResponse> search(
      UUID owner, String query, String sort, String direction, int page, int size);

  List<AppDtos.AppUserView> listUsers(UUID owner, UUID appId, int page, int size);

  AppDtos.AppResponse get(UUID owner, UUID id);

  AppDtos.AppResponse update(UUID owner, UUID id, AppDtos.UpdateAppRequest request);

  AppDtos.RotatedSecretResponse rotate(UUID owner, UUID id);

  AppDtos.AppUserView updateUser(
      UUID owner, UUID appId, UUID userId, AppDtos.UpdateAppUserRequest request);

  void deleteUser(UUID owner, UUID appId, UUID userId);

  com.authplatform.app.entity.App findByPublishableKey(String key);
}
