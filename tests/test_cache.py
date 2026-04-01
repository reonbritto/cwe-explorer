"""Tests for Redis cache layer — storage, retrieval, TTL, and concurrent users.

Uses fakeredis for in-process testing without a real Redis server.
"""

import pytest

from app.cache import (
    _hash_query,
    cleanup_expired,
    get_all_cached_cves,
    get_cache_stats,
    get_cached_cve,
    get_cached_search,
    set_cached_cve,
    set_cached_search,
    register_active_user,
    refresh_active_user,
    remove_active_user,
    get_active_user_count,
)


def _make_fake_redis():
    """Create an in-memory fake Redis client for testing."""
    try:
        import fakeredis
        return fakeredis.FakeRedis(decode_responses=True)
    except ImportError:
        pytest.skip("fakeredis not installed — skipping Redis tests")


@pytest.fixture(autouse=True)
def _fake_redis(monkeypatch):
    """Patch _get_redis to return a fakeredis instance for every test."""
    fake = _make_fake_redis()
    monkeypatch.setattr("app.cache._get_redis", lambda: fake)
    yield fake
    fake.flushall()


class TestCveCache:
    def test_set_and_get_cve(self):
        cve_data = {"cve_id": "CVE-2021-44228", "desc": "Log4j"}
        set_cached_cve("CVE-2021-44228", cve_data)
        result = get_cached_cve("CVE-2021-44228")
        assert result is not None
        assert result["cve_id"] == "CVE-2021-44228"

    def test_get_missing_cve_returns_none(self):
        result = get_cached_cve("CVE-9999-00000")
        assert result is None

    def test_cve_cache_overwrites_on_duplicate(self):
        set_cached_cve("CVE-2021-44228", {"version": 1})
        set_cached_cve("CVE-2021-44228", {"version": 2})
        result = get_cached_cve("CVE-2021-44228")
        assert result["version"] == 2

    def test_get_all_cached_cves(self):
        set_cached_cve("CVE-2024-00001", {"id": "one"})
        set_cached_cve("CVE-2024-00002", {"id": "two"})
        all_cves = get_all_cached_cves()
        assert isinstance(all_cves, list)
        assert len(all_cves) >= 2


class TestSearchCache:
    def test_set_and_get_search(self):
        data = {"results": [1, 2, 3]}
        set_cached_search("query=injection", data)
        result = get_cached_search("query=injection")
        assert result is not None
        assert result["results"] == [1, 2, 3]

    def test_get_missing_search_returns_none(self):
        result = get_cached_search("nonexistent-query-params")
        assert result is None

    def test_different_queries_have_different_hashes(self):
        h1 = _hash_query("query=injection")
        h2 = _hash_query("query=overflow")
        assert h1 != h2

    def test_hash_is_deterministic(self):
        h1 = _hash_query("test-query")
        h2 = _hash_query("test-query")
        assert h1 == h2


class TestCleanup:
    def test_cleanup_is_noop(self):
        """Redis TTL handles expiry — cleanup_expired returns 0."""
        set_cached_cve("CVE-2020-00001", {"old": True})
        removed = cleanup_expired()
        assert removed == 0


class TestCacheStats:
    def test_stats_returns_counts(self):
        set_cached_cve("CVE-2024-10001", {"test": True})
        stats = get_cache_stats()
        assert "cve_entries" in stats
        assert "search_entries" in stats
        assert "redis_used_memory_bytes" in stats
        assert stats["cve_entries"] >= 1


class TestConcurrentUsers:
    def test_first_user_admitted(self):
        assert register_active_user("user-1") is True

    def test_duplicate_user_always_admitted(self):
        register_active_user("user-1")
        assert register_active_user("user-1") is True

    def test_user_limit_enforced(self, monkeypatch):
        monkeypatch.setattr("app.cache.MAX_CONCURRENT_USERS", 2)
        assert register_active_user("user-a") is True
        assert register_active_user("user-b") is True
        assert register_active_user("user-c") is False

    def test_remove_user_frees_slot(self, monkeypatch):
        monkeypatch.setattr("app.cache.MAX_CONCURRENT_USERS", 2)
        register_active_user("user-a")
        register_active_user("user-b")
        remove_active_user("user-a")
        assert register_active_user("user-c") is True

    def test_active_user_count(self):
        register_active_user("user-x")
        register_active_user("user-y")
        assert get_active_user_count() >= 2

    def test_refresh_user(self):
        register_active_user("user-r")
        refresh_active_user("user-r")
        assert get_active_user_count() >= 1
