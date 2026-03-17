"""
Geo-location service — IP extraction and GeoIP lookup.

Uses ip-api.com (free, no API key needed, 45 req/min limit).
Results are cached in Redis for 24 hours to minimize API calls.
"""

import logging
import json
import ipaddress
from typing import Optional
from fastapi import Request

logger = logging.getLogger(__name__)

# Cache TTL for geo lookups — 24 hours
GEO_CACHE_TTL = 86400


def _normalize_ip(raw_ip: str) -> str:
    """Normalize common proxy IP formats (including host:port and [ipv6]:port)."""
    if not raw_ip:
        return ""

    ip = raw_ip.strip()

    # IPv6 with brackets and optional port: [2001:db8::1]:443
    if ip.startswith("[") and "]" in ip:
        ip = ip[1:ip.index("]")]
    # IPv4 with port: 203.0.113.7:8080
    elif ip.count(":") == 1 and "." in ip:
        ip = ip.split(":", 1)[0]

    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ""


def get_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting reverse-proxy headers."""
    candidate_headers = [
        request.headers.get("CF-Connecting-IP"),
        request.headers.get("X-Forwarded-For"),
        request.headers.get("X-Real-IP"),
        request.headers.get("X-Client-IP"),
    ]

    for value in candidate_headers:
        if not value:
            continue
        first = value.split(",", 1)[0].strip()
        normalized = _normalize_ip(first)
        if normalized:
            return normalized

    if request.client and request.client.host:
        normalized = _normalize_ip(request.client.host)
        if normalized:
            return normalized

    return "unknown"


def get_location(ip: str) -> dict:
    """
    Look up geographic location for an IP address.
    Returns dict with city, region, country, lat, lon, isp.
    Results are cached in Redis for 24 hours.
    """
    if not ip or ip in ("unknown", "localhost", "testclient"):
        return {}

    normalized_ip = _normalize_ip(ip)
    if not normalized_ip:
        return {}

    ip_obj = ipaddress.ip_address(normalized_ip)
    if (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return {}

    cache_key = f"geo:{normalized_ip}"

    # Check Redis cache first
    try:
        from app.redis import redis_client
        cached = redis_client.get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception:
        pass  # Redis unavailable — proceed with API call

    # Call providers in order; first success wins.
    try:
        import requests as http_requests

        providers = [
            (
                "ip-api",
                f"http://ip-api.com/json/{normalized_ip}?fields=status,city,regionName,country,lat,lon,isp",
            ),
            ("ipwhois", f"https://ipwho.is/{normalized_ip}"),
        ]

        for provider_name, provider_url in providers:
            try:
                resp = http_requests.get(provider_url, timeout=3)
                data = resp.json()

                if provider_name == "ip-api":
                    if data.get("status") != "success":
                        continue
                    result = {
                        "city": data.get("city", ""),
                        "region": data.get("regionName", ""),
                        "country": data.get("country", ""),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp", ""),
                    }
                else:
                    if not data.get("success"):
                        continue
                    result = {
                        "city": data.get("city", ""),
                        "region": data.get("region", ""),
                        "country": data.get("country", ""),
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                        "isp": data.get("connection", {}).get("isp", ""),
                    }

                # Cache in Redis
                try:
                    from app.redis import redis_client

                    redis_client.setex(cache_key, GEO_CACHE_TTL, json.dumps(result))
                except Exception:
                    pass

                return result
            except Exception as provider_error:
                logger.debug(f"Geo provider {provider_name} failed for {normalized_ip}: {provider_error}")
    except Exception as e:
        logger.warning(f"GeoIP lookup failed for {normalized_ip}: {e}")

    return {}


def record_login_event(
    db,
    user_id: Optional[int],
    app_id: Optional[str],
    tenant_id: Optional[int],
    request: Request,
    event_type: str,
):
    """
    Record an authentication event with IP and geolocation data.
    This is fire-and-forget — errors are logged but never block the auth flow.
    """
    try:
        from app.models.login_event import LoginEvent

        ip = get_client_ip(request)
        geo = get_location(ip)

        event = LoginEvent(
            user_id=user_id,
            app_id=app_id,
            tenant_id=tenant_id,
            event_type=event_type,
            ip_address=ip,
            city=geo.get("city"),
            region=geo.get("region"),
            country=geo.get("country"),
            lat=geo.get("lat"),
            lon=geo.get("lon"),
            isp=geo.get("isp"),
        )
        db.add(event)
        db.commit()
    except Exception as e:
        logger.warning(f"Failed to record login event: {e}")
        try:
            db.rollback()
        except Exception:
            pass
