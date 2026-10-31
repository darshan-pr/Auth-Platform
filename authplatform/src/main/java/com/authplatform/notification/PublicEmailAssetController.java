package com.authplatform.notification;

import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import com.authplatform.common.exception.ApiException;
import com.authplatform.common.exception.ErrorCode;
import java.io.IOException;
import java.time.Duration;
import java.util.UUID;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/public")
public class PublicEmailAssetController {
  private static final String PLATFORM_ICON = "auth-platform-icon-black.png";
  private final AppRepository apps;

  public PublicEmailAssetController(AppRepository apps) {
    this.apps = apps;
  }

  @GetMapping("/app-icons/{appId}")
  ResponseEntity<byte[]> appIcon(@PathVariable UUID appId) {
    App app =
        apps.findById(appId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    return image(app.getIconData(), app.getIconContentType());
  }

  @GetMapping("/email-assets/platform-icon")
  ResponseEntity<byte[]> platformIcon() {
    try (var icon = new ClassPathResource(PLATFORM_ICON).getInputStream()) {
      return image(icon.readAllBytes(), "image/png");
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to load the Auth Platform email icon", ex);
    }
  }

  private ResponseEntity<byte[]> image(byte[] content, String contentType) {
    if (content == null || contentType == null) {
      throw new ApiException(ErrorCode.NOT_FOUND);
    }
    MediaType mediaType =
        switch (contentType) {
          case "image/png" -> MediaType.IMAGE_PNG;
          case "image/jpeg" -> MediaType.IMAGE_JPEG;
          case "image/webp" -> MediaType.parseMediaType("image/webp");
          default -> throw new IllegalStateException("Unsupported stored app icon content type");
        };
    return ResponseEntity.ok()
        .contentType(mediaType)
        .cacheControl(CacheControl.maxAge(Duration.ofHours(1)).cachePublic())
        .header("X-Content-Type-Options", "nosniff")
        .body(content);
  }
}
