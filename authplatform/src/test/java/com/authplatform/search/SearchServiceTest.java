package com.authplatform.search;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.authplatform.search.SearchDtos.Hit;
import com.authplatform.search.SearchDtos.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class SearchServiceTest {
  private static Hit hit(Type type, int n) {
    return new Hit(type, "id" + n, "name" + n, null, null, null, null);
  }

  @Test
  void shortQueriesDoNotTouchTheDatabase() {
    SearchRepository repository = mock(SearchRepository.class);
    var response = new SearchService(repository).searchPlatform(" a ", 5);

    assertThat(response.groups()).isEmpty();
    verifyNoInteractions(repository);
  }

  @Test
  void trimsExtraRowToReportMoreResultsAndClampsTheLimit() {
    SearchRepository repository = mock(SearchRepository.class);
    List<Hit> six = new ArrayList<>();
    for (int i = 0; i < 6; i++) six.add(hit(Type.APPLICATION, i));
    UUID owner = UUID.randomUUID();
    when(repository.applications(any(), eq(owner), eq(5))).thenReturn(six);
    when(repository.endUsers(any(), eq(owner), anyInt())).thenReturn(List.of());

    var response = new SearchService(repository).searchOwned(owner, "Acme", 0);

    assertThat(response.query()).isEqualTo("acme");
    assertThat(response.groups()).hasSize(1);
    assertThat(response.groups().get(0).items()).hasSize(5);
    assertThat(response.groups().get(0).hasMore()).isTrue();
  }

  @Test
  void ownedSearchNeverQueriesAccountsOrAuditLogs() {
    SearchRepository repository = mock(SearchRepository.class);
    new SearchService(repository).searchOwned(UUID.randomUUID(), "acme", 5);

    org.mockito.Mockito.verify(repository, org.mockito.Mockito.never()).accounts(any(), anyInt());
    org.mockito.Mockito.verify(repository, org.mockito.Mockito.never()).auditEvents(any(), any(), anyInt());
  }
}
