"""Extract URL references from already-collected passive evidence only."""

from collections import OrderedDict
from html.parser import HTMLParser
import re
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree


class _ReferenceParser(HTMLParser):
    _URL_ATTRIBUTES = {"href", "src", "action", "poster"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() in self._URL_ATTRIBUTES and value:
                self.references.append(value.strip())

    handle_startendtag = handle_starttag


def normalize_candidate(resource: Any, base_url: Any) -> tuple[str, bool] | None:
    if not isinstance(resource, str) or not resource.strip():
        return None
    value = resource.strip()
    if "\\" in value or any(character.isspace() for character in value) or re.search(r"%(?![0-9a-fA-F]{2})", value):
        return None
    try:
        base = urlsplit(str(base_url or ""))
        parsed = urlsplit(urljoin(str(base_url or ""), value))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        host = parsed.hostname.lower()
        if not all(character.isalnum() or character in ".:-" for character in host):
            return None
        port = parsed.port
        default_port = (parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)
        netloc = host if port is None or default_port else f"{host}:{port}"
        path = "/" + "/".join(part for part in parsed.path.split("/") if part)
        normalized = urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
        same_host = bool(base.hostname and host == base.hostname.lower())
        if same_host and (base.port is None or port in (None, base.port, 80 if base.scheme == "http" else 443)):
            return urlunsplit(("", "", path, parsed.query, "")), False
        return normalized, True
    except (ValueError, TypeError):
        return None


def _sitemap_locations(content: Any) -> list[str]:
    if not isinstance(content, str) or not content.strip():
        return []
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return []
    return [node.text.strip() for node in root.iter() if node.tag.rsplit("}", 1)[-1].lower() == "loc" and node.text and node.text.strip()]


def _requested_statuses(http: dict, base_url: Any) -> dict[str, int | None]:
    requested: dict[str, int | None] = {}
    raw_items = http.get("requested_resources")
    if isinstance(raw_items, list):
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            normalized = normalize_candidate(item.get("url"), base_url)
            if normalized and not normalized[1]:
                try:
                    requested[normalized[0]] = int(item["status_code"]) if item.get("status_code") is not None else None
                except (TypeError, ValueError):
                    requested[normalized[0]] = None
    # Compatibility for existing stored reports: the final URL is response
    # evidence for that exact URL only, never for sibling candidate paths.
    if not raw_items:
        normalized = normalize_candidate(http.get("final_url"), base_url)
        if normalized and not normalized[1]:
            try:
                requested[normalized[0]] = int(http["status_code"]) if http.get("status_code") is not None else None
            except (TypeError, ValueError):
                requested[normalized[0]] = None
    return requested


def extract_exposure_candidates(payload: dict) -> list[dict]:
    normalized_target = payload.get("normalized_target") if isinstance(payload.get("normalized_target"), dict) else {}
    modules = payload.get("modules") if isinstance(payload.get("modules"), dict) else {}
    http = modules.get("http") if isinstance(modules.get("http"), dict) else {}
    base_url = normalized_target.get("base_url") or http.get("requested_url") or http.get("final_url")
    candidates: OrderedDict[str, dict] = OrderedDict()

    def add(resource: Any, source: str, evidence: str) -> None:
        normalized = normalize_candidate(resource, base_url)
        if normalized is None:
            return
        value, external = normalized
        item = candidates.setdefault(value, {
            "resource": value,
            "sources": [],
            "evidence": [],
            "external": external,
        })
        if source not in item["sources"]:
            item["sources"].append(source)
        if evidence and evidence not in item["evidence"]:
            item["evidence"].append(evidence)
        item["external"] = item["external"] or external

    robots = modules.get("robots") if isinstance(modules.get("robots"), dict) else {}
    if robots.get("status") == "ok":
        for line in str(robots.get("content") or "").splitlines():
            match = re.match(r"\s*(?:Disallow|Allow)\s*:\s*(.*?)\s*(?:#.*)?$", line, re.IGNORECASE)
            if match:
                reference = match.group(1).strip()
                if not reference.startswith("//"):
                    add(reference, "robots.txt", line.strip())

    sitemap = modules.get("sitemap") if isinstance(modules.get("sitemap"), dict) else {}
    for result in sitemap.get("results", []):
        if isinstance(result, dict) and result.get("status") == "found":
            for location in _sitemap_locations(result.get("content")):
                add(location, "sitemap.xml", location)

    http_module = modules.get("http") if isinstance(modules.get("http"), dict) else {}
    content = http_module.get("content")
    if isinstance(content, str) and content:
        parser = _ReferenceParser()
        try:
            parser.feed(content)
        except Exception:
            parser.references.clear()
        for reference in parser.references:
            add(reference, "HTML", reference)

    requested_statuses = _requested_statuses(http_module, base_url)
    request_failed = str(http_module.get("status", "")).lower() in {"error", "failed"}
    for item in candidates.values():
        status_code = requested_statuses.get(item["resource"])
        checked = item["resource"] in requested_statuses
        item.update({
            "checked": checked,
            "http_status": status_code,
            "category": "Requires Review" if item["external"] else "Publicly Referenced",
        })
        if item["checked"] and not item["external"]:
            item["category"] = "Check Failed" if status_code is None and request_failed else "HTTP Response Observed" if status_code is not None else "Request Observed"
    return list(candidates.values())
