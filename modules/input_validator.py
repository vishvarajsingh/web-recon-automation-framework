"""Validate and normalize user-supplied targets."""

import re
from typing import Any, Dict
from urllib.parse import urlparse


class ValidationError(ValueError):
    """Raised when the target input is invalid."""


def normalize_target(target: str) -> Dict[str, Any]:
    """Return a normalized target structure or a structured error."""
    cleaned = (target or "").strip()
    if not cleaned:
        return {"valid": False, "error": "No target supplied."}

    if re.search(r"[\s\\]", cleaned):
        return {"valid": False, "error": "Target contains whitespace or shell-like characters."}

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"}:
            return {"valid": False, "error": "Only http and https URLs are supported."}
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return {"valid": False, "error": "URL is missing a hostname."}
        if not re.match(r"^[a-z0-9.-]+$", hostname):
            return {"valid": False, "error": "Hostname contains unsupported characters."}
        return {
            "valid": True,
            "hostname": hostname,
            "scheme": parsed.scheme,
            "base_url": f"{parsed.scheme}://{hostname}",
            "path": parsed.path or "/",
        }

    if re.match(r"^[a-z0-9.-]+$", cleaned.lower()):
        hostname = cleaned.lower()
        return {
            "valid": True,
            "hostname": hostname,
            "scheme": "https",
            "base_url": f"https://{hostname}",
            "path": "/",
        }

    return {"valid": False, "error": "Target is not a valid domain or URL."}
