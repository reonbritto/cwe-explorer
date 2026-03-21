"""SQLite-backed cache for NVD API responses."""
import json
import os
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cve_cache.db")
TTL_HOURS = 24


def _get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            cve_id TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS search_cache (
            query_hash TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def _is_expired(fetched_at: str) -> bool:
    fetched = datetime.fromisoformat(fetched_at)
    return datetime.utcnow() - fetched > timedelta(hours=TTL_HOURS)


def get_cached_cve(cve_id: str) -> Optional[dict]:
    """Retrieve cached CVE data if not expired."""
    conn = _get_connection()
    try:
        # Use parameterized query to prevent SQL injection
        cursor = conn.execute(
            "SELECT response_json, fetched_at FROM cve_cache WHERE cve_id = ?",
            (cve_id,)
        )
        row = cursor.fetchone()
        if row and not _is_expired(row[1]):
            return json.loads(row[0])
        return None
    finally:
        conn.close()


def set_cached_cve(cve_id: str, data: dict) -> None:
    """Store CVE data in cache."""
    conn = _get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (cve_id, response_json, fetched_at) VALUES (?, ?, ?)",
            (cve_id, json.dumps(data), datetime.utcnow().isoformat())
        )
        conn.commit()
    finally:
        conn.close()


def _hash_query(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()


def get_cached_search(query_params: str) -> Optional[dict]:
    """Retrieve cached search results if not expired."""
    query_hash = _hash_query(query_params)
    conn = _get_connection()
    try:
        cursor = conn.execute(
            "SELECT response_json, fetched_at FROM search_cache WHERE query_hash = ?",
            (query_hash,)
        )
        row = cursor.fetchone()
        if row and not _is_expired(row[1]):
            return json.loads(row[0])
        return None
    finally:
        conn.close()


def set_cached_search(query_params: str, data: dict) -> None:
    """Store search results in cache."""
    query_hash = _hash_query(query_params)
    conn = _get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO search_cache "
            "(query_hash, response_json, fetched_at) "
            "VALUES (?, ?, ?)",
            (query_hash, json.dumps(data),
             datetime.utcnow().isoformat())
        )
        conn.commit()
    finally:
        conn.close()


def get_all_cached_cves() -> list:
    """Retrieve all cached CVE data for analytics."""
    conn = _get_connection()
    try:
        cursor = conn.execute(
            "SELECT response_json FROM cve_cache"
        )
        return [json.loads(row[0]) for row in cursor.fetchall()]
    finally:
        conn.close()
