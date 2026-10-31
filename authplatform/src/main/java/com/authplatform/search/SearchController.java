package com.authplatform.search;

import com.authplatform.common.security.AuthenticatedPrincipal;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
  private final SearchService service;

  public SearchController(SearchService service) {
    this.service = service;
  }

  @GetMapping("/api/sa/search")
  ResponseEntity<SearchDtos.Response> platform(
      @RequestParam(defaultValue = "") String q, @RequestParam(defaultValue = "5") int limit) {
    return noStore(service.searchPlatform(q, limit));
  }

  @GetMapping("/api/console/search")
  ResponseEntity<SearchDtos.Response> owned(
      @AuthenticationPrincipal AuthenticatedPrincipal principal,
      @RequestParam(defaultValue = "") String q,
      @RequestParam(defaultValue = "5") int limit) {
    return noStore(service.searchOwned(principal.subjectId(), q, limit));
  }

  private static ResponseEntity<SearchDtos.Response> noStore(SearchDtos.Response body) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
  }
}
