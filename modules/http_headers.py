"""Collect basic passive HTTP response metadata."""

import logging
from typing import Any, Dict

import requests

logger = logging.getLogger("web_recon")


def gather_http_headers(base_url: str) -> Dict[str, Any]:
    """Fetch HTTP metadata while failing gracefully."""
    try:
        response = requests.get(
            base_url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "WebReconAutomationFramework/1.0"},
        )
        return {
            "status": "ok",
            "status_code": response.status_code,
            "final_url": response.url,
            "response_time_seconds": round(response.elapsed.total_seconds(), 3),
            "server": response.headers.get("server", ""),
            "content_type": response.headers.get("content-type", ""),
            "cookies": dict(response.cookies),
            "cache_headers": {
                "cache_control": response.headers.get("cache-control", ""),
                "etag": response.headers.get("etag", ""),
                "last_modified": response.headers.get("last-modified", ""),
            },
            "redirect_chain": [item.url for item in response.history],
        }
    except Exception as exc:  # pragma: no cover
        logger.warning("HTTP analysis failed for %s: %s", base_url, exc)
        return {"status": "error", "error": str(exc)}
