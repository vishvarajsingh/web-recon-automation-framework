import logging
from typing import Dict

import requests
from bs4 import BeautifulSoup

from modules.network_policy import read_response_text, safe_get

logger = logging.getLogger("web_recon")


def gather_robots(base_url: str) -> Dict[str, object]:
    robots_url = f"{base_url}/robots.txt"
    try:
        response = safe_get(robots_url, timeout=5, stream=True)
        if response.status_code != 200:
            response.close()
            return {"status": "not_found", "url": robots_url}
        content, truncated = read_response_text(response)
        return {"status": "ok", "url": robots_url, "content": content, "content_truncated": truncated}
    except Exception as exc:  # pragma: no cover
        logger.warning("robots.txt lookup failed for %s: %s", base_url, exc)
        return {"status": "failed", "error": str(exc)}
