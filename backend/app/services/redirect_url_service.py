from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


def normalize_redirect_uri(raw: str) -> Optional[tuple[str, object]]:
    candidate = (raw or "").strip().strip("\"'")
    if not candidate:
        return None

    parsed = urlparse(candidate)

    # Accept scheme-less entries like "myapp.example.com/callback".
    if not parsed.scheme and "://" not in candidate:
        candidate = f"https://{candidate.lstrip('/')}"
        parsed = urlparse(candidate)

    if parsed.scheme in ("http", "https") and parsed.netloc:
        return candidate, parsed
    return None


def is_localhost_target(parsed) -> bool:
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} or host.endswith(".localhost")


def infer_app_signin_url(
    redirect_uris: Optional[str],
    allow_localhost_fallback: bool = False,
) -> Optional[str]:
    if not redirect_uris:
        return None

    valid = []
    for raw in redirect_uris.split(","):
        normalized = normalize_redirect_uri(raw)
        if normalized:
            valid.append(normalized)

    if not valid:
        return None

    public = [(candidate, parsed) for candidate, parsed in valid if not is_localhost_target(parsed)]
    pool = public if public else (valid if allow_localhost_fallback else [])
    if not pool:
        return None

    for candidate, parsed in pool:
        path = (parsed.path or "").lower()
        if "signin" in path or "sign-in" in path or "login" in path:
            return candidate

    candidate, parsed = pool[0]
    first_path = (parsed.path or "").lower()
    if "callback" in first_path or "oauth" in first_path:
        return f"{parsed.scheme}://{parsed.netloc}/login"
    return candidate


def append_query_params(url: str, params: Optional[dict]) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in (params or {}).items():
        if value is not None and value != "":
            query[str(key)] = str(value)
    return urlunparse(parsed._replace(query=urlencode(query)))


def build_server_signin_url(client_id: str, source: str = "password_reset") -> str:
    return f"/signin?{urlencode({'client_id': client_id, 'from': source})}"


def build_auth_platform_login_url(auth_platform_base_url: str) -> str:
    base = (auth_platform_base_url or "").strip()
    if not base:
        return "/login"
    if base.startswith(("http://", "https://")):
        return urljoin(base.rstrip("/") + "/", "login")

    normalized = base.rstrip("/")
    if not normalized:
        return "/login"
    return f"{normalized}/login"
