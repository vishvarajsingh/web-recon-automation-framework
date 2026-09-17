"""Collect basic passive HTTP response metadata."""

import logging
from typing import Any, Dict

import requests

from modules.network_policy import MAX_RESPONSE_CONTENT_BYTES, read_response_text, safe_get

REQUEST_TIMEOUT_SECONDS = 8
logger = logging.getLogger("web_recon")


def gather_http_headers(base_url: str) -> Dict[str, Any]:
    """Fetch HTTP metadata while failing gracefully."""
    try:
        response = safe_get(
            base_url,
            timeout=(REQUEST_TIMEOUT_SECONDS, REQUEST_TIMEOUT_SECONDS),
            stream=True,
            headers={"User-Agent": "WebReconAutomationFramework/1.0"},
        )
        content, content_truncated = read_response_text(response)
        return {
            "status": "ok",
            "status_code": response.status_code,
            "final_url": response.url,
            "response_time_seconds": round(response.elapsed.total_seconds(), 3),
            "server": response.headers.get("server", ""),
            "content_type": response.headers.get("content-type", ""),
            "content": content,
            "content_truncated": content_truncated,
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
