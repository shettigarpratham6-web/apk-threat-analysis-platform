import hmac
import os
import uuid

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str | None = Security(_header)) -> None:
    expected = os.environ.get("API_KEY", "")
    if not expected:
        return
    if not key or not hmac.compare_digest(key, expected):
        raise HTTPException(401, "Invalid or missing API key")


def validate_apk_id(apk_id: str) -> str:
    try:
        return str(uuid.UUID(apk_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(400, "Invalid apk_id")
