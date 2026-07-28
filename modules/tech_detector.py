"""Detect common technologies from headers and HTML content."""

import logging
from typing import Dict, List

import requests

logger = logging.getLogger("web_recon")


def detect_technology(base_url: str) -> Dict[str, object]:
    """Look for common technologies using passive indicators."""
    try:
        response = requests.get(base_url, timeout=8, headers={"User-Agent": "WebReconAutomationFramework/1.0"})
        text = (response.text or "").lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        detected: List[str] = []

        if "server" in headers and "apache" in headers["server"].lower():
            detected.append("Apache")
        if "server" in headers and "nginx" in headers["server"].lower():
            detected.append("Nginx")
        if "server" in headers and "iis" in headers["server"].lower():
            detected.append("IIS")
        if "server" in headers and "cloudflare" in headers["server"].lower():
            detected.append("Cloudflare")
        if "x-powered-by" in headers and "php" in headers["x-powered-by"].lower():
            detected.append("PHP")
        if "express" in text:
            detected.append("Express")
        if "asp.net" in text or ("x-powered-by" in headers and "asp.net" in headers["x-powered-by"].lower()):
            detected.append("ASP.NET")
        if "wp-content" in text or "wordpress" in text:
            detected.append("WordPress")

        return {"status": "ok", "technologies": detected}
    except Exception as exc:  # pragma: no cover
        logger.warning("Technology detection failed for %s: %s", base_url, exc)
        return {"status": "error", "error": str(exc)}
