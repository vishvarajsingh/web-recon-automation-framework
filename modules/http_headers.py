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
        requested_resources = [
            {"url": item.url, "status_code": item.status_code}
            for item in response.history
        ]
        requested_resources.append({"url": response.url, "status_code": response.status_code})
        cookie_attributes = {}
        for cookie in response.cookies:
            attributes = {str(key).lower(): value for key, value in getattr(cookie, "_rest", {}).items()}
            cookie_attributes[cookie.name] = {
                "domain": cookie.domain or None,
                "path": cookie.path or None,
                "secure": bool(cookie.secure),
                "http_only": bool(cookie.has_nonstandard_attr("HttpOnly") or "httponly" in attributes),
                "same_site": attributes.get("samesite"),
                "expires": cookie.expires,
            }
        return {
            "status": "ok",
            "status_code": response.status_code,
            "requested_url": base_url,
            "requested_resources": requested_resources,
            "final_url": response.url,
            "response_time_seconds": round(response.elapsed.total_seconds(), 3),
            "server": response.headers.get("server", ""),
            "content_type": response.headers.get("content-type", ""),
            "content": content,
            "content_truncated": content_truncated,
            "cookies": dict(response.cookies),
            "cookie_attributes": cookie_attributes,
            "cache_headers": {
                "cache_control": response.headers.get("cache-control", ""),
                "etag": response.headers.get("etag", ""),
                "last_modified": response.headers.get("last-modified", ""),
            },
            "redirect_chain": [item.url for item in response.history],
        }
    except Exception as exc:  # pragma: no cover
        logger.warning("HTTP analysis failed for %s: %s", base_url, exc)
        return {
            "status": "error",
            "requested_url": base_url,
            "requested_resources": [{"url": base_url, "status_code": None}],
            "error": str(exc),
        }
