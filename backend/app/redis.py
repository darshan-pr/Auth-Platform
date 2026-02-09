import redis
from app.config import settings
import logging

logger = logging.getLogger(__name__)

try:
    redis_client = redis.Redis.from_url(
        settings.REDIS_URL, 
        decode_responses=True,
        socket_connect_timeout=5
    )
    # Test connection
    redis_client.ping()
    logger.info("Redis connection established")
except redis.ConnectionError as e:
    logger.error(f"Failed to connect to Redis: {e}")
    raise

