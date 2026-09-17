import logging
from typing import Dict

import requests

from modules.network_policy import read_response_text, safe_get

logger = logging.getLogger("web_recon")


def gather_sitemap(base_url: str) -> Dict[str, object]:
    sitemap_urls = [f"{base_url}/sitemap.xml", f"{base_url}/sitemap_index.xml"]
    results = []
    for url in sitemap_urls:
        try:
            response = safe_get(url, timeout=5, stream=True)
            if response.status_code == 200:
                content, truncated = read_response_text(response)
                results.append({"url": url, "status": "found", "content": content, "content_truncated": truncated})
            else:
                response.close()
                results.append({"url": url, "status": "not_found"})
        except Exception as exc:  # pragma: no cover
            logger.warning("Sitemap lookup failed for %s: %s", url, exc)
            results.append({"url": url, "status": "failed", "error": str(exc)})
    statuses = [item["status"] for item in results]
    if any(status == "found" for status in statuses):
        status = "partial" if any(item_status == "failed" for item_status in statuses) else "ok"
    elif any(item_status == "failed" for item_status in statuses):
        status = "failed"
    else:
        status = "not_found"
    return {"status": status, "results": results}
