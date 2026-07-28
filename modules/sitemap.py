import logging
from typing import Dict

import requests

logger = logging.getLogger("web_recon")


def gather_sitemap(base_url: str) -> Dict[str, object]:
    sitemap_urls = [f"{base_url}/sitemap.xml", f"{base_url}/sitemap_index.xml"]
    results = []
    for url in sitemap_urls:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                results.append({"url": url, "status": "found", "content": response.text})
            else:
                results.append({"url": url, "status": "not_found"})
        except Exception as exc:  # pragma: no cover
            logger.warning("Sitemap lookup failed for %s: %s", url, exc)
            results.append({"url": url, "status": "failed", "error": str(exc)})
    return {"results": results}
