"""
Redis-backed sliding window rate limiter.

Usage as a FastAPI dependency:
    from app.services.rate_limiter import create_rate_limit_dependency

    rate_limit_login = create_rate_limit_dependency("login", max_requests=5, window_seconds=60)

    @router.post("/login")
    def login(request: Request, _=Depends(rate_limit_login)):
        ...
"""

import time
import logging
from fastapi import Request, HTTPException, status

logger = logging.getLogger(__name__)


def get_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting reverse-proxy headers."""
    # X-Forwarded-For can contain a chain: "client, proxy1, proxy2"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def format_retry_after(seconds: int) -> str:
    """Format seconds into a human-readable duration string."""
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        parts = [f"{minutes} minute{'s' if minutes != 1 else ''}"]
        if remaining_seconds:
            parts.append(f"{remaining_seconds} second{'s' if remaining_seconds != 1 else ''}")
        return " and ".join(parts)
    else:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        parts = [f"{hours} hour{'s' if hours != 1 else ''}"]
        if remaining_minutes:
            parts.append(f"{remaining_minutes} minute{'s' if remaining_minutes != 1 else ''}")
        return " and ".join(parts)


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
    """
    Sliding window rate limit check using Redis sorted sets.

    Returns (is_allowed, retry_after_seconds).
    """
    try:
        from app.redis import redis_client
        now = time.time()
        window_start = now - window_seconds

        pipe = redis_client.pipeline()
        # Remove expired entries
        pipe.zremrangebyscore(key, 0, window_start)
        # Count entries in the current window
        pipe.zcard(key)
        # Add the current request
        pipe.zadd(key, {f"{now}": now})
        # Set TTL so keys auto-expire
        pipe.expire(key, window_seconds + 1)
        results = pipe.execute()

        current_count = results[1]

        if current_count >= max_requests:
            # Calculate retry-after from the oldest entry in the window
            oldest = redis_client.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(oldest[0][1] + window_seconds - now) + 1
            else:
                retry_after = window_seconds
            return False, max(retry_after, 1)

        return True, 0
    except Exception as e:
        logger.warning(f"Rate limiter error (allowing request): {e}")
        return True, 0  # Fail open — don't block users if Redis is down


def create_rate_limit_dependency(
    endpoint_name: str,
    max_requests: int,
    window_seconds: int = 20,
):
    """
    Factory that returns a FastAPI dependency for rate limiting.

    Args:
        endpoint_name: A short label used in the Redis key (e.g. "login", "signup").
        max_requests: Maximum requests allowed in the window.
        window_seconds: Sliding window size in seconds (default 3600).
    """
    async def rate_limit(request: Request):
        client_ip = get_client_ip(request)
        key = f"rate:{endpoint_name}:{client_ip}"
        allowed, retry_after = check_rate_limit(key, max_requests, window_seconds)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. Please try again in {format_retry_after(retry_after)}.",
                headers={"Retry-After": str(retry_after)},
            )

    return rate_limit