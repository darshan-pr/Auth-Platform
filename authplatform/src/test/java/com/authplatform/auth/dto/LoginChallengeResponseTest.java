package com.authplatform.auth.dto;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class LoginChallengeResponseTest {
  @Test
  void mfaChallengeContainsNoIdentityOrSessionFields() throws Exception {
    String json =
        new ObjectMapper()
            .writeValueAsString(
                new AuthDtos.LoginChallengeResponse(
                    false, true, "challenge-id", 300, "Check your email."));

    assertThat(json)
        .isEqualTo(
            "{\"authenticated\":false,\"otpRequired\":true,\"challengeId\":\"challenge-id\",\"expiresIn\":300,\"message\":\"Check your email.\"}");
  }
}
