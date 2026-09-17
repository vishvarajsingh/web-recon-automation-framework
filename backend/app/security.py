from fastapi import Header, HTTPException, status

from .core.config import settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend authentication is not configured",
        )
    if x_api_key != settings.API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")