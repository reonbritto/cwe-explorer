"""Microsoft Entra ID JWT validation for FastAPI.

Supports two authentication methods:
1. Entra ID Bearer JWT  — for browser / user access (MSAL.js)
2. Service API key       — for internal tools (Locust, monitoring)

Set SERVICE_API_KEY env var to enable the API key bypass.
"""
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt import PyJWKClient, decode as jwt_decode, PyJWTError

CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

# Service API key for internal tools (Locust, scripts, health probes)
# If not set explicitly, generate a random key and log it at startup
SERVICE_API_KEY = os.environ.get("SERVICE_API_KEY", "")

security = HTTPBearer(auto_error=True)

# ── JWKS caching ─────────────────────────────────────────────
_jwks_client: Optional[PyJWKClient] = None
_jwks_created_at: Optional[datetime] = None
_JWKS_TTL = timedelta(hours=1)


def _get_jwks_client() -> PyJWKClient:
    """Return a cached PyJWKClient, refreshing after TTL expires."""
    global _jwks_client, _jwks_created_at
    now = datetime.now(timezone.utc)
    if (
        _jwks_client is None
        or _jwks_created_at is None
        or now - _jwks_created_at > _JWKS_TTL
    ):
        _jwks_client = PyJWKClient(JWKS_URL)
        _jwks_created_at = now
    return _jwks_client


# ── FastAPI dependency ────────────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> dict:
    """Validate a Bearer token and return its claims.

    Accepts either:
    - A Microsoft Entra ID JWT (RS256, validated against JWKS)
    - A service API key (for internal tools like Locust)

    Raises HTTP 401 if the token is missing, expired, or invalid.
    """
    token = credentials.credentials

    # ── Check service API key first (fast path) ──────────────
    if SERVICE_API_KEY and secrets.compare_digest(token, SERVICE_API_KEY):
        return {
            "sub": "service-account",
            "name": "Internal Service",
            "iss": "service-api-key",
        }

    # ── Fall back to Entra ID JWT validation ─────────────────
    try:
        jwks_client = _get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt_decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            options={"verify_iss": False, "verify_exp": True},
            issuer=None,  # Entra ID uses multiple issuers; audience check is sufficient
        )
        return payload
    except PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )
