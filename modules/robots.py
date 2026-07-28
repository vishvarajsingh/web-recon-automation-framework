import logging
from typing import Dict

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("web_recon")


def gather_robots(base_url: str) -> Dict[str, object]:
    robots_url = f"{base_url}/robots.txt"
    try:
        response = requests.get(robots_url, timeout=5)
        if response.status_code != 200:
            return {"status": "not_found", "url": robots_url}
        return {"status": "ok", "url": robots_url, "content": response.text}
    except Exception as exc:  # pragma: no cover
        logger.warning("robots.txt lookup failed for %s: %s", base_url, exc)
        return {"status": "failed", "error": str(exc)}
