package com.authplatform.common.config;

import com.authplatform.auth.security.AppKeyAuthenticationFilter;
import com.authplatform.auth.security.AppOriginValidationFilter;
import com.authplatform.auth.security.JwtAuthenticationFilter;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.authplatform.common.security.PlatformAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
  @Value("${authplatform.security.console-allowed-origins}")
  private String consoleAllowedOrigins;

  @Value("${authplatform.security.docs-enabled:true}")
  private boolean docsEnabled;

  @Value("${authplatform.security.cookie-secure:true}")
  private boolean secureCookies;

  @Bean
  SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      JwtAuthenticationFilter jwt,
      AppKeyAuthenticationFilter key,
      AppOriginValidationFilter origin)
      throws Exception {
    CookieCsrfTokenRepository csrfTokens = CookieCsrfTokenRepository.withHttpOnlyFalse();
    csrfTokens.setSecure(secureCookies);
    http.csrf(
            csrf ->
                csrf.csrfTokenRepository(csrfTokens)
                    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                    .ignoringRequestMatchers(
                        "/api/console/auth/**",
                        "/api/sa/auth/**",
                        "/api/v1/auth/**",
                        // The SDK BFF validates CSRF; this backend endpoint uses bearer auth.
                        "/api/v1/users/me/sessions/**"))
        .exceptionHandling(e -> e.authenticationEntryPoint(new PlatformAuthenticationEntryPoint()))
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            a ->
                a.requestMatchers("/api/console/csrf", "/api/sa/csrf")
                    .permitAll()
                    .requestMatchers("/api/console/mfa/**", "/api/sa/mfa/**", "/api/v1/auth/mfa/**")
                    .authenticated()
                    .requestMatchers(
                        "/api/console/auth/**",
                        "/api/sa/auth/**",
                        "/api/v1/auth/**",
                        "/.well-known/jwks.json",
                        "/actuator/health")
                    .permitAll()
                    .requestMatchers("/swagger-ui/**", "/v3/api-docs/**")
                    .access(
                        (authentication, context) ->
                            new org.springframework.security.authorization.AuthorizationDecision(
                                docsEnabled))
                    .requestMatchers("/actuator/**")
                    .denyAll()
                    .requestMatchers("/api/sa/**")
                    .hasRole("SA")
                    .requestMatchers("/api/console/**", "/api/v1/users/**")
                    .authenticated()
                    .anyRequest()
                    .denyAll())
        .addFilterBefore(key, UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(origin, AppKeyAuthenticationFilter.class)
        .addFilterAfter(jwt, AppOriginValidationFilter.class)
        .headers(
            h ->
                h.contentTypeOptions(c -> {})
                    .frameOptions(f -> f.deny())
                    .referrerPolicy(
                        r ->
                            r.policy(
                                org.springframework.security.web.header.writers
                                    .ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                    .contentSecurityPolicy(
                        c ->
                            c.policyDirectives(
                                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"))
                    .httpStrictTransportSecurity(
                        s -> s.includeSubDomains(true).maxAgeInSeconds(31536000)));
    return http.build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    List<String> methods = List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
    List<String> headers =
        List.of(
            "Content-Type",
            "Authorization",
            "X-authplatform-Key",
            "X-Requested-With",
            "X-Request-Id",
            "X-XSRF-TOKEN");
    CorsConfiguration sdk = new CorsConfiguration();
    sdk.setAllowedOriginPatterns(List.of("*"));
    sdk.setAllowedMethods(methods);
    sdk.setAllowedHeaders(headers);
    sdk.setAllowCredentials(false);
    CorsConfiguration console = new CorsConfiguration();
    List<String> configuredConsoleOrigins =
        Arrays.stream(consoleAllowedOrigins.split(","))
            .map(String::trim)
            .filter(value -> !value.isBlank())
            .toList();
    console.setAllowedOrigins(configuredConsoleOrigins);
    console.setAllowedMethods(methods);
    console.setAllowedHeaders(headers);
    console.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/v1/**", sdk);
    source.registerCorsConfiguration("/api/console/**", console);
    source.registerCorsConfiguration("/api/sa/**", console);
    source.registerCorsConfiguration("/actuator/**", console);
    source.registerCorsConfiguration("/.well-known/**", console);
    return source;
  }
}
