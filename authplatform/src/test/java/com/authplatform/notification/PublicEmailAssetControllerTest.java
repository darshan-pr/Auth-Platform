package com.authplatform.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authplatform.app.entity.App;
import com.authplatform.app.repository.AppRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

class PublicEmailAssetControllerTest {
  private final AppRepository apps = mock(AppRepository.class);
  private final PublicEmailAssetController controller = new PublicEmailAssetController(apps);

  @Test
  void servesUploadedAppIconsAsCacheableImages() {
    UUID appId = UUID.fromString("95f59855-df58-4e31-9ec8-51f9814187a6");
    App app = mock(App.class);
    when(apps.findById(appId)).thenReturn(Optional.of(app));
    when(app.getIconData()).thenReturn(new byte[] {1, 2, 3});
    when(app.getIconContentType()).thenReturn("image/png");

    var response = controller.appIcon(appId);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.IMAGE_PNG);
    assertThat(response.getHeaders().getCacheControl()).contains("public");
    assertThat(response.getBody()).containsExactly(1, 2, 3);
  }

  @Test
  void servesThePlatformIconAsAnImage() {
    var response = controller.platformIcon();

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.IMAGE_PNG);
    assertThat(response.getBody()).isNotEmpty();
  }
}
