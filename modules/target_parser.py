import re
from typing import Any, Dict
from urllib.parse import urlparse


def parse_target(target: str) -> Dict[str, Any]:
    cleaned = (target or "").strip()
    if not cleaned:
        return {"valid": False, "reason": "No target supplied"}

    if re.search(r"[\s\\]", cleaned):
        return {"valid": False, "reason": "Target contains whitespace or shell-like characters"}

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"}:
            return {"valid": False, "reason": "Only http/https URLs are supported"}
        hostname = parsed.hostname or ""
        if not hostname:
            return {"valid": False, "reason": "URL is missing a hostname"}
        if not re.match(r"^[a-z0-9.-]+$", hostname.lower()):
            return {"valid": False, "reason": "Hostname contains unsupported characters"}
        return {
            "valid": True,
            "hostname": hostname.lower(),
            "scheme": parsed.scheme,
            "base_url": f"{parsed.scheme}://{hostname}",
        }

    if re.match(r"^[a-z0-9.-]+$", cleaned.lower()):
        return {
            "valid": True,
            "hostname": cleaned.lower(),
            "scheme": "https",
            "base_url": f"https://{cleaned.lower()}",
        }

    return {"valid": False, "reason": "Target is not a valid domain or URL"}
