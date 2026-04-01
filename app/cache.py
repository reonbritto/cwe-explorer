"""Redis-backed cache for NVD API responses and concurrent user enforcement."""
import json
import os
import hashlib
import logging
from typing import Optional

import redis

logger = logging.getLogger("cwe-explorer")

# ── Redis connection config ──────────────────────────────────────
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", 3600))  # 1 hour

# ── Concurrent user limit ───────────────────────────────────────
MAX_CONCURRENT_USERS = int(os.environ.get("MAX_CONCURRENT_USERS", "3"))
USER_SESSION_TTL = int(os.environ.get("USER_SESSION_TTL", "1800"))  # 30 min

# Redis key prefixes
_CVE_PREFIX = "cve:"
_SEARCH_PREFIX = "search:"
_ACTIVE_USERS_KEY = "active_users"

# Lazy-initialised connection pool
_pool: Optional[redis.ConnectionPool] = None


def _get_redis() -> redis.Redis:
    """Return a Redis client backed by a shared connection pool."""
    global _pool
    if _pool is None:
        _pool = redis.ConnectionPool.from_url(
            REDIS_URL, decode_responses=True
        )
    return redis.Redis(connection_pool=_pool)


# ── CVE cache ────────────────────────────────────────────────────


def get_cached_cve(cve_id: str) -> Optional[dict]:
    """Retrieve cached CVE data (returns None on miss or error)."""
    try:
        r = _get_redis()
        data = r.get(f"{_CVE_PREFIX}{cve_id}")
        if data:
            return json.loads(data)
    except redis.RedisError as e:
        logger.warning("Redis get_cached_cve error: %s", e)
    return None


def set_cached_cve(cve_id: str, data: dict) -> None:
    """Store CVE data in Redis with TTL."""
    try:
        r = _get_redis()
        r.setex(
            f"{_CVE_PREFIX}{cve_id}",
            TTL_SECONDS,
            json.dumps(data),
        )
    except redis.RedisError as e:
        logger.warning("Redis set_cached_cve error: %s", e)


# ── Search cache ─────────────────────────────────────────────────


def _hash_query(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()


def get_cached_search(query_params: str) -> Optional[dict]:
    """Retrieve cached search results (returns None on miss or error)."""
    try:
        r = _get_redis()
        data = r.get(f"{_SEARCH_PREFIX}{_hash_query(query_params)}")
        if data:
            return json.loads(data)
    except redis.RedisError as e:
        logger.warning("Redis get_cached_search error: %s", e)
    return None


def set_cached_search(query_params: str, data: dict) -> None:
    """Store search results in Redis with TTL."""
    try:
        r = _get_redis()
        r.setex(
            f"{_SEARCH_PREFIX}{_hash_query(query_params)}",
            TTL_SECONDS,
            json.dumps(data),
        )
    except redis.RedisError as e:
        logger.warning("Redis set_cached_search error: %s", e)


# ── Bulk retrieval (analytics) ───────────────────────────────────


def get_all_cached_cves() -> list:
    """Retrieve all cached CVE data for analytics.

    Uses SCAN to iterate over cve:* keys without blocking Redis.
    """
    results = []
    try:
        r = _get_redis()
        cursor = 0
        while True:
            cursor, keys = r.scan(
                cursor=cursor, match=f"{_CVE_PREFIX}*", count=200
            )
            if keys:
                values = r.mget(keys)
                for v in values:
                    if v:
                        results.append(json.loads(v))
            if cursor == 0:
                break
    except redis.RedisError as e:
        logger.warning("Redis get_all_cached_cves error: %s", e)
    return results


# ── Cleanup (no-op — Redis TTL handles expiry automatically) ─────


def cleanup_expired() -> int:
    """No-op: Redis expires keys automatically via TTL.

    Retained for API compatibility with startup and health checks.
    Returns 0 because there is nothing to clean up manually.
    """
    return 0


# ── Cache stats ──────────────────────────────────────────────────


def get_cache_stats() -> dict:
    """Return cache size metrics from Redis."""
    try:
        r = _get_redis()
        # Count keys by prefix using SCAN (non-blocking)
        cve_count = 0
        search_count = 0

        cursor = 0
        while True:
            cursor, keys = r.scan(cursor=cursor, match=f"{_CVE_PREFIX}*", count=500)
            cve_count += len(keys)
            if cursor == 0:
                break

        cursor = 0
        while True:
            cursor, keys = r.scan(cursor=cursor, match=f"{_SEARCH_PREFIX}*", count=500)
            search_count += len(keys)
            if cursor == 0:
                break

        try:
            info = r.info("memory")
            used_memory = info.get("used_memory", 0)
        except redis.RedisError:
            used_memory = 0

        return {
            "cve_entries": cve_count,
            "search_entries": search_count,
            "redis_used_memory_bytes": used_memory,
        }
    except redis.RedisError as e:
        logger.warning("Redis get_cache_stats error: %s", e)
        return {
            "cve_entries": 0,
            "search_entries": 0,
            "redis_used_memory_bytes": 0,
        }


# ── Concurrent user enforcement ──────────────────────────────────


def register_active_user(user_oid: str) -> bool:
    """Try to register a user as active.

    Returns True if the user was admitted (already active OR under limit).
    Returns False if the concurrent-user cap has been reached.
    """
    try:
        r = _get_redis()

        # Already registered? Just refresh the TTL and allow.
        if r.zscore(_ACTIVE_USERS_KEY, user_oid) is not None:
            r.zadd(_ACTIVE_USERS_KEY, {user_oid: _now_ts()})
            return True

        # Evict expired sessions first
        _evict_expired_users(r)

        # Check capacity
        active_count = r.zcard(_ACTIVE_USERS_KEY)
        if active_count >= MAX_CONCURRENT_USERS:
            return False

        # Register the new user
        r.zadd(_ACTIVE_USERS_KEY, {user_oid: _now_ts()})
        return True
    except redis.RedisError as e:
        logger.warning("Redis register_active_user error: %s", e)
        # Fail-open: allow the request if Redis is down
        return True


def refresh_active_user(user_oid: str) -> None:
    """Refresh the TTL for an already-registered user."""
    try:
        r = _get_redis()
        r.zadd(_ACTIVE_USERS_KEY, {user_oid: _now_ts()})
    except redis.RedisError as e:
        logger.warning("Redis refresh error: %s", e)


def remove_active_user(user_oid: str) -> None:
    """Explicitly remove a user (e.g. on logout)."""
    try:
        r = _get_redis()
        r.zrem(_ACTIVE_USERS_KEY, user_oid)
    except redis.RedisError as e:
        logger.warning("Redis remove_active_user error: %s", e)


def get_active_user_count() -> int:
    """Return the number of currently active users."""
    try:
        r = _get_redis()
        _evict_expired_users(r)
        return r.zcard(_ACTIVE_USERS_KEY)
    except redis.RedisError as e:
        logger.warning("Redis get_active_user_count error: %s", e)
        return 0


def _now_ts() -> float:
    """Current time as a Unix timestamp (for sorted-set scores)."""
    import time
    return time.time()


def _evict_expired_users(r: redis.Redis) -> None:
    """Remove users whose session timestamp is older than USER_SESSION_TTL."""
    import time
    cutoff = time.time() - USER_SESSION_TTL
    r.zremrangebyscore(_ACTIVE_USERS_KEY, "-inf", cutoff)
