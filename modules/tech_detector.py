"""Identify technologies from explicit, passively collected response indicators."""

import logging
import re
from collections import OrderedDict
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from modules.network_policy import read_response_text, safe_get

logger = logging.getLogger("web_recon")


class _TechnologyHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.generators: list[str] = []
        self.assets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value for name, value in attrs if value is not None}
        if tag.lower() == "meta" and values.get("name", "").strip().lower() == "generator":
            if values.get("content", "").strip():
                self.generators.append(values["content"].strip())
        if tag.lower() in {"script", "link", "img", "source"}:
            for name in ("src", "href", "srcset"):
                value = values.get(name)
                if value:
                    self.assets.append(value.strip())

    handle_startendtag = handle_starttag


def _record(detections: OrderedDict, name: str, source: str, value: Any, confidence: str = "Medium") -> None:
    item = detections.setdefault(name, {"name": name, "confidence": confidence, "evidence": []})
    if confidence == "High":
        item["confidence"] = "High"
    observation = {"source": source, "value": value}
    if observation not in item["evidence"]:
        item["evidence"].append(observation)
    if len({evidence["source"] for evidence in item["evidence"]}) > 1:
        item["confidence"] = "High"


def detect_technology(base_url: str) -> dict[str, Any]:
    """Return supported fingerprints with their observed source and confidence."""
    try:
        response = safe_get(base_url, timeout=8, stream=True, headers={"User-Agent": "WebReconAutomationFramework/1.0"})
        text, truncated = read_response_text(response)
        response_status = response.status_code
        headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        cookies = list(response.cookies)
        parser = _TechnologyHTMLParser()
        try:
            parser.feed(text)
        except Exception:
            truncated = True

        detections: OrderedDict[str, dict] = OrderedDict()
        server = headers.get("server", "")
        for signature, name in (("apache", "Apache"), ("nginx", "Nginx"), ("microsoft-iis", "IIS"), ("cloudflare", "Cloudflare")):
            if re.search(rf"(?<![a-z0-9]){re.escape(signature)}(?![a-z0-9])", server, re.IGNORECASE):
                _record(detections, name, "Server header", server)

        powered_by = headers.get("x-powered-by", "")
        for signature, name in ((r"\bphp(?:[/\s]|$)", "PHP"), (r"\basp\.net\b", "ASP.NET"), (r"\bexpress(?:\.js)?\b", "Express")):
            if re.search(signature, powered_by, re.IGNORECASE):
                _record(detections, name, "X-Powered-By header", powered_by)

        for generator in parser.generators:
            for signature, name in (
                (r"\bwordpress\b", "WordPress"), (r"\bdrupal\b", "Drupal"),
                (r"\bjoomla\b", "Joomla"), (r"\bnext\.js\b", "Next.js"),
                (r"\bnuxt(?:\.js)?\b", "Nuxt"), (r"\bdjango\b", "Django"),
            ):
                if re.search(signature, generator, re.IGNORECASE):
                    _record(detections, name, "HTML meta generator", generator)

        for cookie in cookies:
            cookie_name = cookie.name
            lowered = cookie_name.lower()
            cookie_evidence = {
                "name": cookie_name,
                "domain": cookie.domain or None,
                "path": cookie.path or None,
                "secure": bool(cookie.secure),
                "http_only": bool(cookie.has_nonstandard_attr("HttpOnly")),
                "same_site": getattr(cookie, "_rest", {}).get("SameSite"),
            }
            if lowered == "phpsessid":
                _record(detections, "PHP", "Cookie name and attributes", cookie_evidence)
            elif lowered == "laravel_session":
                _record(detections, "Laravel", "Cookie name and attributes", cookie_evidence)
            elif lowered.startswith("wordpress_"):
                _record(detections, "WordPress", "Cookie name and attributes", cookie_evidence)
            elif lowered == "connect.sid":
                _record(detections, "Express", "Cookie name and attributes", cookie_evidence)

        base = response.url
        for reference in parser.assets:
            absolute = urljoin(base, reference)
            path = urlsplit(absolute).path.lower()
            for signature, name in (
                ("/wp-content/", "WordPress"), ("/wp-includes/", "WordPress"),
                ("/_next/", "Next.js"), ("/_nuxt/", "Nuxt"),
                ("/sites/default/files/", "Drupal"),
            ):
                if signature in path:
                    _record(detections, name, "HTML asset URL", absolute)

        values = list(detections.values())
        complete = not truncated and 200 <= response_status < 400
        status = "incomplete" if not complete else "identified" if values else "no_match"
        return {
            "status": status,
            "complete": complete,
            "http_status": response_status,
            "technologies": [item["name"] for item in values],
            "detections": values,
            "message": (
                "Technology evidence is incomplete because the response was truncated or returned a non-success status. Detected items are partial and no-match conclusions are inconclusive."
                if not complete else "Supported passive indicators were identified."
                if values else "No supported technology was identified in the complete collected passive indicators."
            ),
        }
    except Exception as exc:  # pragma: no cover - exercised with deterministic monkeypatches
        logger.warning("Technology detection failed for %s: %s", base_url, exc)
        return {"status": "failed", "complete": False, "technologies": [], "detections": [], "error": str(exc),
                "message": "Technology detection failed; no conclusion can be made."}
