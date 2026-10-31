import { useCallback, useEffect, useRef, useState } from "react";
import type { PageResponse } from "./types";

export const TABLE_PREFERENCES_EVENT = "authplatform:table-preferences";
const PAGE_SIZES = [10, 20, 50];

export function tablePreferencesKey(tableId: string): string {
  return `authplatform.table-preferences.${tableId}`;
}

/** Page size saved from a table's Preferences dialog, or the default when none is saved. */
export function readPageSize(tableId: string, fallback = 20): number {
  if (typeof window === "undefined") return fallback;
  try {
    const saved = JSON.parse(window.localStorage.getItem(tablePreferencesKey(tableId)) ?? "{}") as { pageSize?: number };
    return PAGE_SIZES.includes(saved.pageSize ?? 0) ? (saved.pageSize as number) : fallback;
  } catch {
    return fallback;
  }
}

export function usePageSize(tableId: string, fallback = 20): number {
  const [size, setSize] = useState(() => readPageSize(tableId, fallback));
  useEffect(() => {
    const read = () => setSize(readPageSize(tableId, fallback));
    read();
    window.addEventListener(TABLE_PREFERENCES_EVENT, read);
    return () => window.removeEventListener(TABLE_PREFERENCES_EVENT, read);
  }, [tableId, fallback]);
  return size;
}

export type ListParams = { q: string; sort: string; direction: "asc" | "desc"; size: number };

/**
 * State for a table whose search, sorting and paging all run on the server: a debounced filter,
 * sortable columns, the saved page size, and protection against out-of-order responses.
 * `deps` lists outside values (such as a status filter) that should trigger a reload.
 */
export function useServerList<T, K extends string>({
  tableId,
  fetchPage,
  initialQuery = "",
  initialSort,
  deps = [],
}: {
  tableId: string;
  fetchPage: (page: number, params: ListParams) => Promise<PageResponse<T>>;
  initialQuery?: string;
  initialSort: { key: K; direction: "asc" | "desc" };
  deps?: unknown[];
}) {
  const pageSize = usePageSize(tableId);
  const [items, setItems] = useState<T[]>([]);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [filter, setFilter] = useState(initialQuery);
  const [query, setQuery] = useState(initialQuery);
  const [sortKey, setSortKey] = useState<K>(initialSort.key);
  const [sortDirection, setSortDirection] = useState(initialSort.direction);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(0);
  const requestId = useRef(0);
  const fetchRef = useRef(fetchPage);
  fetchRef.current = fetchPage;

  // Typing updates the box immediately but only queries the server once the user pauses.
  useEffect(() => {
    if (filter === query) return;
    const timer = window.setTimeout(() => { setQuery(filter); setPage(0); }, 300);
    return () => window.clearTimeout(timer);
  }, [filter, query]);
  useEffect(() => { setFilter(initialQuery); setQuery(initialQuery); setPage(0); }, [initialQuery]);
  useEffect(() => { setPage(0); }, [pageSize]);

  useEffect(() => {
    const current = ++requestId.current;
    setLoading(true);
    setError("");
    fetchRef.current(page, { q: query, sort: sortKey, direction: sortDirection, size: pageSize })
      .then((result) => {
        if (current !== requestId.current) return;
        setItems(result.items);
        setTotalPages(Math.max(result.totalPages, 1));
        setTotalItems(result.totalItems);
        if (result.page !== page) setPage(result.page);
      })
      .catch((err) => { if (current === requestId.current) setError(err instanceof Error ? err.message : "Unable to load this list"); })
      .finally(() => { if (current === requestId.current) setLoading(false); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, query, sortKey, sortDirection, pageSize, tick, ...deps]);

  const toggleSort = useCallback((key: K) => {
    if (key === sortKey) setSortDirection((current) => (current === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDirection("asc"); }
    setPage(0);
  }, [sortKey]);
  const reload = useCallback(() => setTick((value) => value + 1), []);
  const clearFilter = useCallback(() => { setFilter(""); setQuery(""); setPage(0); }, []);

  return { items, page, setPage, totalPages, totalItems, pageSize, filter, setFilter, query, sortKey, sortDirection, toggleSort, loading, error, reload, clearFilter };
}
