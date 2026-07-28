"""Perform a passive WHOIS lookup for the target."""

import logging
from datetime import date, datetime
from typing import Any, Dict

try:
    import whois as python_whois
except Exception:  # pragma: no cover
    python_whois = None

logger = logging.getLogger("web_recon")


def _normalize(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def gather_whois_info(hostname: str) -> Dict[str, Any]:
    """Return WHOIS data or a structured error payload."""
    if python_whois is None:
        return {"status": "error", "error": "python-whois is not installed"}

    try:
        result = python_whois.whois(hostname)
        return {
            "status": "ok",
            "domain_name": _normalize(getattr(result, "domain_name", None)),
            "registrar": _normalize(getattr(result, "registrar", None)),
            "creation_date": _normalize(getattr(result, "creation_date", None)),
            "expiration_date": _normalize(getattr(result, "expiration_date", None)),
            "updated_date": _normalize(getattr(result, "updated_date", None)),
            "name_servers": _normalize(getattr(result, "name_servers", None)),
        }
    except Exception as exc:  # pragma: no cover
        logger.warning("WHOIS lookup failed for %s: %s", hostname, exc)
        return {"status": "error", "error": str(exc)}
