import logging
from typing import Dict

import requests

from modules.network_policy import safe_get

logger = logging.getLogger("web_recon")


def gather_security_headers(base_url: str) -> Dict[str, object]:
    try:
        response = safe_get(base_url, timeout=5, stream=True)
        headers = response.headers
        checks = {
            "strict_transport_security": headers.get("strict-transport-security", ""),
            "content_security_policy": headers.get("content-security-policy", ""),
            "x_frame_options": headers.get("x-frame-options", ""),
            "x_content_type_options": headers.get("x-content-type-options", ""),
            "referrer_policy": headers.get("referrer-policy", ""),
        }
        response.close()
        return {"status": "ok", "headers": checks}
    except Exception as exc:  # pragma: no cover
        logger.warning("Security-header inspection failed for %s: %s", base_url, exc)
        return {"status": "failed", "error": str(exc)}
