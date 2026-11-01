import json
import re
from copy import deepcopy
from html import escape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence
from urllib.parse import quote, urlsplit, urlunsplit
from xml.etree import ElementTree


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_COLORS = {
    "Critical": "#d32f2f",
    "High": "#f57c00",
    "Medium": "#fbc02d",
    "Low": "#388e3c",
    "Informational": "#1976d2",
}
DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
DNS_EXPLANATIONS = {
    "A": "Points a hostname to an IPv4 address.",
    "AAAA": "Points a hostname to an IPv6 address.",
    "MX": "Identifies mail servers for the domain.",
    "NS": "Identifies the domain's DNS name servers.",
    "TXT": "Stores text-based DNS information, often used for verification and email policies.",
    "CNAME": "Points one hostname to another hostname.",
}
SECURITY_HEADER_EXPLANATIONS = {
    "strict_transport_security": "Asks browsers to use secure HTTPS connections.",
    "content_security_policy": "Helps limit which sources a browser may load content from.",
    "x_frame_options": "Controls whether other sites can display this page in a frame.",
    "x_content_type_options": "Helps prevent browsers from guessing a different content type.",
    "referrer_policy": "Controls how much page address information is shared with other sites.",
}
WHOIS_FIELDS = {
    "domain_name": ("Domain Name", "Domain name returned by the registration lookup."),
    "registrar": ("Registrar", "Organization listed as managing the domain registration."),
    "creation_date": ("Created", "Creation date reported by the registration lookup."),
    "expiration_date": ("Expiration Date", "Expiration date reported by the registration lookup."),
    "updated_date": ("Last Updated", "Most recent update date reported by the registration lookup."),
    "name_servers": ("Name Servers", "DNS servers listed by the registration lookup."),
}


def _display_text(value: Any, fallback: str = "n/a") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, (list, tuple, set)):
        if not value:
            return fallback
        return ", ".join(_display_text(item, fallback) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _display_path(raw_path: Any, default_name: str) -> str:
    if not raw_path:
        return default_name
    candidate = str(raw_path)
    parsed = Path(candidate)
    name = parsed.name or candidate.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return name or default_name


def _sanitize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = deepcopy(payload)
    report_paths = cleaned.get("report_paths")
    if isinstance(report_paths, dict):
        cleaned["report_paths"] = {
            "json": _display_path(report_paths.get("json"), "report.json"),
            "html": _display_path(report_paths.get("html"), "report.html"),
        }
    return cleaned


def _status_label(status: Any) -> str:
    labels = {
        "ok": "Available", "success": "Available", "partial": "Partially Available",
        "found": "Found", "no_answer": "No Answer", "not_found": "Not Found",
        "nxdomain": "Failed", "timeout": "Failed", "error": "Failed",
        "failed": "Failed", "not_https": "Not Applicable",
    }
    if status is None or status == "":
        return "Not Checked"
    return labels.get(str(status).lower(), str(status).replace("_", " ").title())


def _badge(label: str, status: str = "") -> str:
    normalized = status.lower()
    if normalized in {"ok", "success", "found"}:
        color = "#16804a"
    elif normalized == "low":
        color = "#388e3c"
    elif normalized == "medium":
        color = "#b7791f"
    elif normalized == "high":
        color = "#c05621"
    elif normalized == "critical":
        color = "#b42318"
    elif normalized == "informational":
        color = "#1976d2"
    elif normalized in {"no_answer", "not_found", "not_https"}:
        color = "#64748b"
    elif normalized in {"failed", "error", "timeout", "nxdomain"}:
        color = "#b42318"
    else:
        color = "#475569"
    return f"<span class='badge status-badge' style='background:{color};'>{escape(label)}</span>"


def _value_html(value: Any, empty: str = "Not returned") -> str:
    if value is None or value == "" or value == []:
        return escape(empty)
    if isinstance(value, (list, tuple, set)):
        return "<div class='value-list'>" + "".join(
            f"<div>{escape(_display_text(item, empty))}</div>" for item in value
        ) + "</div>"
    return escape(_display_text(value, empty))


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]], class_name: str = "report-table") -> str:
    header_html = "".join(f"<th scope='col'>{escape(header)}</th>" for header in headers)
    row_html = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    if not row_html:
        row_html = f"<tr><td colspan='{len(headers)}' class='empty-cell'>No results were returned.</td></tr>"
    return f"<div class='table-wrap'><table class='{class_name}'><thead><tr>{header_html}</tr></thead><tbody>{row_html}</tbody></table></div>"


def _section(title: str, body: str, section_id: str = "") -> str:
    identifier = f" id='{escape(section_id, quote=True)}'" if section_id else ""
    return f"<section class='panel'{identifier}><h2>{escape(title)}</h2>{body}</section>"


def _dns_rows(dns: Dict[str, Any]) -> tuple[list[list[str]], dict[str, Any]]:
    records = dns.get("records") if isinstance(dns.get("records"), dict) else {}
    rows: list[list[str]] = []
    for record_type in DNS_RECORD_TYPES:
        record = records.get(record_type)
        if not isinstance(record, dict):
            record = {}
        raw_status = record.get("status")
        values = record.get("values")
        if raw_status == "ok":
            status_label = "Found"
            value = _value_html(values)
        elif raw_status == "no_answer":
            status_label = "No Answer"
            value = "No answer received"
        elif raw_status == "nxdomain":
            status_label = "Failed"
            value = "The DNS lookup returned NXDOMAIN; no record values were returned."
        elif raw_status in {"error", "timeout"}:
            status_label = "Failed"
            value = _value_html(record.get("error"), "Lookup failed; record existence is unknown.")
        else:
            status_label = "Not Checked"
            value = "Not checked"
        rows.append([
            escape(record_type), _badge(status_label, str(raw_status or "not_checked")),
            value, escape(DNS_EXPLANATIONS[record_type]),
        ])
    return rows, records


def _render_dns_section(dns: Dict[str, Any], hostname: Any) -> str:
    records = dns.get("records") if isinstance(dns.get("records"), dict) else {}
    rows, records = _dns_rows(dns)
    dns_hostname = dns.get("hostname") or hostname
    overall_status = dns.get("status")
    status_result = _badge(_status_label(overall_status), str(overall_status or "not_checked"))

    def address_count(record_type: str) -> str:
        record = records.get(record_type)
        if not isinstance(record, dict) or not record.get("status"):
            return "Not checked"
        if record.get("status") == "ok":
            values = record.get("values")
            return str(len(values)) if isinstance(values, (list, tuple)) else ("1" if values else "0")
        if record.get("status") == "no_answer":
            return "0"
        return "Unavailable"

    summary_rows = [
        ["Target Hostname", _value_html(dns_hostname), "Hostname used for the DNS queries."],
        ["DNS Lookup Status", status_result, "Overall result of the DNS record checks."],
        ["IPv4 Addresses Found", escape(address_count("A")), "Number of IPv4 values returned by the A-record lookup."],
        ["IPv6 Addresses Found", escape(address_count("AAAA")), "Number of IPv6 values returned by the AAAA-record lookup."],
    ]
    return _section(
        "DNS Summary",
        _table(["Metric", "Result", "What It Means"], summary_rows, "report-table dns-summary")
        + "<h3>DNS Records</h3>"
        + _table(["Record Type", "Status", "Value", "What It Means"], rows, "report-table dns-records"),
        "dns-information",
    )


def _render_ip_section(ip_info: Dict[str, Any]) -> str:
    status = ip_info.get("status")
    if status in {"error", "failed"}:
        ipv4 = "Lookup failed; addresses are unknown."
        ipv6 = "Lookup failed; addresses are unknown."
        reverse = "Lookup failed; reverse DNS is unknown."
    else:
        ipv4 = _value_html(ip_info.get("ipv4"), "None returned")
        ipv6 = _value_html(ip_info.get("ipv6"), "None returned")
        reverse = _value_html(ip_info.get("reverse_dns"), "Unavailable")
    rows = [
        ["IPv4 Addresses", ipv4, "Addresses using IPv4."],
        ["IPv6 Addresses", ipv6, "Addresses using IPv6."],
        ["Reverse DNS", reverse, "Names returned by reverse DNS lookups. This does not prove server ownership or identity."],
    ]
    return _section("IP Address Information", _table(["Metric", "Result", "Explanation"], rows, "report-table ip-table"), "ip-information")


def _render_whois_section(data: Dict[str, Any]) -> str:
    rows = []
    status = data.get("status")
    rows.append(["Lookup Status", _badge(_status_label(status), str(status or "not_checked")), "Result of the domain registration lookup."])
    if status in {"error", "failed"}:
        rows.append(["Details", _value_html(data.get("error"), "Lookup failed."), "The lookup could not provide registration details."])
    else:
        for key, (label, explanation) in WHOIS_FIELDS.items():
            value = data.get(key)
            if value is not None and value != "" and value != []:
                rows.append([escape(label), _value_html(value), escape(explanation)])
    return _section("WHOIS Information", _table(["Metric", "Result", "What It Means"], rows, "report-table whois-table"), "whois-information")


def _render_http_section(data: Dict[str, Any]) -> str:
    rows = []
    status = data.get("status")
    rows.append(["Request Status", _badge(_status_label(status), str(status or "not_checked")), "Whether HTTP response details were collected."])
    if status in {"error", "failed"}:
        rows.append(["Details", _value_html(data.get("error"), "Request failed."), "The response could not be read; this does not indicate why the site is unavailable."])
    else:
        fields = [
            ("HTTP Status Code", data.get("status_code"), "Response code returned by the web server."),
            ("Final URL", data.get("final_url"), "Address reached after any redirects."),
            ("Response Time", f"{data['response_time_seconds']} seconds" if data.get("response_time_seconds") is not None else None, "Time taken to receive the response."),
            ("Server", data.get("server"), "Server software name if provided in the response."),
            ("Content Type", data.get("content_type"), "Type of content returned by the server."),
            ("Redirects", data.get("redirect_chain"), "Earlier addresses visited before the final response."),
        ]
        for label, value, explanation in fields:
            if value is not None and value != "":
                rows.append([escape(label), _value_html(value), escape(explanation)])
        cache_headers = data.get("cache_headers")
        if isinstance(cache_headers, dict):
            for key, value in cache_headers.items():
                if value:
                    rows.append([escape(f"Cache: {key.replace('_', ' ').title()}"), _value_html(value), "Caching-related value returned by the server."])
    return _section("HTTP Response", _table(["Metric", "Result", "What It Means"], rows, "report-table http-table"), "http-response")


def _render_ssl_section(data: Dict[str, Any]) -> str:
    rows = []
    status = data.get("status")
    rows.append(["Certificate Status", _badge(_status_label(status), str(status or "not_checked")), "Whether TLS certificate details were collected."])
    if status in {"error", "failed"}:
        rows.append(["Details", _value_html(data.get("error"), "Certificate lookup failed."), "Certificate details are unavailable; no conclusion about validity can be made."])
    elif status == "not_https":
        rows.append(["Details", "The final page address did not use HTTPS.", "A TLS certificate was not checked for this address."])
    else:
        fields = [
            ("Certificate Subject", data.get("subject"), "Name the certificate presents."),
            ("Certificate Issuer", data.get("issuer"), "Organization that issued the certificate."),
            ("Valid From", data.get("valid_from"), "Beginning of the certificate validity period."),
            ("Valid Until", data.get("valid_until"), "End of the certificate validity period."),
            ("Days Remaining", data.get("days_remaining"), "Days remaining according to the collected certificate dates."),
            ("Expired", data.get("expired"), "Whether the certificate was expired at scan time."),
            ("Signature Algorithm", data.get("signature_algorithm"), "Algorithm used to sign the certificate."),
            ("Names Covered", data.get("san_entries"), "Hostnames listed on the certificate."),
        ]
        for label, value, explanation in fields:
            if value is not None and value != "":
                rows.append([escape(label), _value_html(value), escape(explanation)])
    return _section("SSL/TLS Certificate", _table(["Metric", "Result", "What It Means"], rows, "report-table ssl-table"), "ssl-certificate")


def _render_security_headers(data: Dict[str, Any]) -> str:
    headers = data.get("headers") if isinstance(data.get("headers"), dict) else {}
    rows = []
    for key, explanation in SECURITY_HEADER_EXPLANATIONS.items():
        observed = headers.get(key)
        if data.get("status") in {"error", "failed"}:
            label = "Failed"
            observed_html = _value_html(data.get("error"), "Header checks failed.")
        elif data.get("status") is None:
            label = "Not Checked"
            observed_html = "Not checked"
        elif observed:
            label = "Present"
            observed_html = _value_html(observed)
        else:
            label = "Not Set"
            observed_html = "No value returned"
        rows.append([escape(key.replace("_", " ").title()), _badge(label, "ok" if label == "Present" else "failed" if label == "Failed" else "not_checked"), observed_html, escape(explanation)])
    return _section("Security Headers", _table(["Security Header", "Status", "Observed Value", "What It Means"], rows, "report-table security-headers-table"), "security-headers")


def _render_technology_section(data: Dict[str, Any]) -> str:
    technologies = data.get("technologies") if isinstance(data.get("technologies"), list) else []
    if data.get("status") in {"error", "failed"}:
        rows = [["Technology check", _badge("Failed", "failed"), _value_html(data.get("error"), "Check failed; no conclusion can be made.")]]
    elif technologies:
        rows = [[escape(str(name)), _badge("Detected", "found"), "Observed from passive page or response indicators."] for name in technologies]
    else:
        rows = [["No technology identified", _badge("None detected", "not_found"), "No supported technology was identified from the collected passive indicators."]]
    return _section("Technology Detection", _table(["Technology", "Result", "What It Means"], rows, "report-table technology-table"), "technology-detection")


def _render_robots_section(data: Dict[str, Any]) -> str:
    status = data.get("status")
    rows = []
    if status in {"error", "failed", "not_found"} or not status:
        message = data.get("error") or ("No robots.txt response was found." if status == "not_found" else "Not checked.")
        rows.append(["robots.txt", _badge(_status_label(status), str(status or "not_checked")), _value_html(data.get("url"), "Not available"), escape(_display_text(message)), "A robots.txt file gives crawler guidance; its rules do not enforce access control."])
    else:
        content = data.get("content", "")
        directives = [line.strip() for line in str(content).splitlines() if line.strip() and not line.lstrip().startswith("#")]
        if directives:
            for directive in directives:
                name, separator, value = directive.partition(":")
                rows.append([escape(name.strip()), _badge("Found", "found"), escape(value.strip() if separator else ""), escape(directive), "Crawler guidance only; these rules do not block visitors or prove that a path is private."])
        else:
            rows.append(["robots.txt", _badge("Found", "found"), _value_html(data.get("url"), "URL not returned"), "No directives were returned.", "An empty robots.txt does not provide crawler restrictions."])
    return _section("robots.txt", _table(["Item", "Status", "Value", "Observed Rule", "What It Means"], rows, "report-table robots-table"), "robots")


def _sitemap_locations(content: Any) -> list[str]:
    if not isinstance(content, str) or not content.strip():
        return []
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return []
    return [element.text.strip() for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "loc" and element.text and element.text.strip()]


def _normalize_candidate(resource: Any, base_url: Any) -> tuple[str, bool] | None:
    if not isinstance(resource, str) or not resource.strip():
        return None
    value = resource.strip()
    if "\\" in value or any(character.isspace() for character in value) or re.search(r"%(?![0-9a-fA-F]{2})", value):
        return None
    try:
        parsed = urlsplit(value)
        base = urlsplit(str(base_url or ""))
        if parsed.scheme or parsed.netloc:
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                return None
            host = parsed.hostname.lower()
            if not re.fullmatch(r"[a-z0-9.:-]+", host):
                return None
            try:
                port = parsed.port
            except ValueError:
                return None
            netloc = host if port is None else f"{host}:{port}"
            path = re.sub(r"/{2,}", "/", parsed.path or "/")
            normalized = urlunsplit((parsed.scheme.lower(), netloc, path.rstrip("/") or "/", parsed.query, ""))
            same_host = bool(base.hostname and host == base.hostname.lower())
            if same_host:
                return urlunsplit(("", "", path.rstrip("/") or "/", parsed.query, "")), False
            return normalized, True

        if not value.startswith("/") or value.startswith("//"):
            return None
        path = re.sub(r"/{2,}", "/", parsed.path or "/")
        normalized = urlunsplit(("", "", path.rstrip("/") or "/", parsed.query, ""))
        return normalized, False
    except (TypeError, ValueError):
        return None


def _extract_exposure_candidates(payload: Dict[str, Any]) -> list[Dict[str, Any]]:
    modules = payload.get("modules") if isinstance(payload.get("modules"), dict) else {}
    normalized = payload.get("normalized_target") if isinstance(payload.get("normalized_target"), dict) else {}
    base_url = normalized.get("base_url")
    candidates: dict[str, Dict[str, Any]] = {}

    def add_candidate(resource: Any, source: str, evidence: str) -> None:
        normalized_candidate = _normalize_candidate(resource, base_url)
        if normalized_candidate is None:
            return
        value, external = normalized_candidate
        entry = candidates.setdefault(value, {"resource": value, "sources": [], "evidence": [], "external": external})
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if evidence and evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)
        entry["external"] = entry["external"] or external

    robots = modules.get("robots") if isinstance(modules.get("robots"), dict) else {}
    if robots.get("status") == "ok":
        for line in str(robots.get("content") or "").splitlines():
            match = re.match(r"\s*(?:Disallow|Allow)\s*:\s*(.*?)\s*(?:#.*)?$", line, re.IGNORECASE)
            if match:
                add_candidate(match.group(1).strip(), "robots.txt", line.strip())

    sitemap = modules.get("sitemap") if isinstance(modules.get("sitemap"), dict) else {}
    for result in sitemap.get("results", []):
        if not isinstance(result, dict) or result.get("status") != "found":
            continue
        for location in _sitemap_locations(result.get("content")):
            add_candidate(location, "sitemap.xml", location)

    http = modules.get("http") if isinstance(modules.get("http"), dict) else {}
    final_url = _normalize_candidate(http.get("final_url"), base_url)
    final_resource = final_url[0] if final_url and not final_url[1] else None
    status_code = http.get("status_code")
    try:
        status_code = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        status_code = None
    if status_code is not None and not 100 <= status_code <= 599:
        status_code = None

    requested_root = _normalize_candidate(base_url, base_url)
    requested_resource = requested_root[0] if requested_root else None
    request_failed = str(http.get("status", "")).lower() in {"error", "failed"}
    for candidate in candidates.values():
        candidate.update({"checked": False, "http_status": None, "category": "Publicly Referenced"})
        if candidate["external"]:
            candidate["category"] = "Requires Review"
        elif status_code is not None and candidate["resource"] == final_resource:
            candidate.update({"checked": True, "http_status": status_code})
            candidate["category"] = "HTTP Accessible" if 200 <= status_code < 300 else "Requires Review"
        elif request_failed and candidate["resource"] == requested_resource:
            candidate.update({"checked": True, "category": "Check Failed"})

    return list(candidates.values())


def _render_exposure_intelligence(payload: Dict[str, Any]) -> str:
    candidates = _extract_exposure_candidates(payload)
    rows = []
    checked_count = sum(1 for candidate in candidates if candidate["checked"])
    for candidate in candidates:
        category = candidate["category"]
        if category == "HTTP Accessible":
            assessment = f"HTTP Accessible: the existing scan received a response for this exact resource (HTTP {candidate['http_status']}); this does not determine authorization."
            action = "Review authentication and authorization within the approved scope."
            status = f"HTTP {candidate['http_status']} · {category}"
        elif category == "Check Failed":
            assessment = "Check Failed: the existing request to this exact resource did not complete; availability is unknown."
            action = "Treat the result as unknown; retry only within the authorized scope."
            status = category
        elif category == "Requires Review":
            assessment = "Requires Review: URL is outside the scanned hostname or returned a non-success status; no access conclusion is made."
            action = "Confirm authorization and scope before any manual follow-up."
            status = f"HTTP {candidate['http_status']} · {category}" if candidate["http_status"] else f"Not checked · {category}"
        else:
            assessment = "Publicly Referenced: this listing alone does not show whether access is restricted."
            action = "Verify access controls manually within the authorized scope."
            status = "Not checked · Publicly Referenced"
        rows.append([
            _value_html(candidate["resource"]),
            escape(", ".join(candidate["sources"])),
            _badge(status, "found" if category == "HTTP Accessible" else "failed" if category == "Check Failed" else "not_checked"),
            _value_html(candidate["evidence"]),
            escape(assessment),
            escape(action),
        ])

    summary_rows = [
        ["Candidate paths discovered", escape(str(len(candidates)))],
        ["Paths actually checked", escape(str(checked_count))],
        ["Path requests made by this feature", "0"],
    ]
    body = _table(["Metric", "Count"], summary_rows, "report-table exposure-intelligence-summary")
    body += _table(
        ["Resource", "Source", "Status", "Evidence", "Assessment", "Recommended Action"],
        rows,
        "report-table exposure-intelligence-table",
    )
    return _section("Exposure Intelligence", body, "exposure-intelligence")


def _render_sitemap_section(data: Dict[str, Any]) -> str:
    results = data.get("results") if isinstance(data.get("results"), list) else []
    rows = []
    for result in results:
        if not isinstance(result, dict):
            continue
        raw_status = result.get("status")
        if raw_status == "found":
            locations = _sitemap_locations(result.get("content"))
            result_value = _value_html(locations, "Sitemap found; no locations were extracted.")
            explanation = "Public sitemap location listed in the response. These entries are discovery information, not access-control results."
        elif raw_status == "failed":
            result_value = _value_html(result.get("error"), "Lookup failed; availability is unknown.")
            explanation = "The sitemap check failed, so its availability is unknown."
        else:
            result_value = "No sitemap response found."
            explanation = "No response was found at this sitemap address; this does not mean the site has no pages."
        rows.append([_value_html(result.get("url"), "URL not returned"), _badge(_status_label(raw_status), str(raw_status or "not_checked")), result_value, explanation])
    if not rows:
        rows.append(["Not checked", _badge("Not Checked", "not_checked"), "No sitemap lookup results were collected.", "No sitemap conclusion can be made."])
    return _section("sitemap.xml", _table(["Sitemap Address", "Status", "Result", "What It Means"], rows, "report-table sitemap-table"), "sitemap")


def _render_findings(findings: list[Dict[str, Any]]) -> str:
    tables = []
    for severity in SEVERITY_ORDER:
        severity_findings = [finding for finding in findings if str(finding.get("severity", "Informational")) == severity]
        if not severity_findings:
            continue
        rows = [[
            _value_html(finding.get("title"), "Finding"), _badge(severity, severity.lower()),
            _value_html(finding.get("confidence"), "Not assessed"),
            _value_html(finding.get("resource"), "Not provided"),
            _value_html(finding.get("source") or finding.get("detection_method"), "Not provided"),
            _value_html(finding.get("evidence"), "No evidence provided"),
            _value_html(finding.get("potential_impact") or finding.get("reason"), "Not assessed"),
            _value_html(finding.get("recommendation"), "No recommendation provided"),
        ] for finding in severity_findings]
        tables.append(f"<h3>{escape(severity)} ({len(rows)})</h3>" + _table(
            ["Finding", "Severity", "Confidence", "Affected Resource", "Detection Method", "Evidence", "Potential Impact", "Recommended Action"],
            rows,
            "report-table findings-table",
        ))
    if not tables:
        tables.append("<p>No findings returned by the detection engine.</p>")
    return _section("Exposure Findings", "".join(tables), "exposure-findings")


def _render_risk(payload: Dict[str, Any], findings: list[Dict[str, Any]]) -> str:
    summary = payload.get("risk_summary") if isinstance(payload.get("risk_summary"), dict) else {}
    risk = payload.get("risk") if isinstance(payload.get("risk"), dict) else {}
    exposure_summary = payload.get("exposure", {}).get("summary", {})
    security_risk = summary.get("security_risk", risk.get("overall_rating"))
    security_score = summary.get("security_score")
    if security_score is None and risk.get("overall_score") is not None:
        security_score = f"{risk['overall_score']}/100"
    exposure_risk = summary.get("exposure_risk", exposure_summary.get("overall_score"))
    rows = [
        ["Security Risk", _badge(_display_text(security_risk, "Not calculated"), str(security_risk or "").lower()), "Calculated from the security checks collected by the scanner."],
        ["Security Score", escape(_display_text(security_score, "Not calculated")), "Score from the framework's security-risk calculation; it is not an exposure count."],
        ["Exposure Risk", _badge(_display_text(exposure_risk, "Not calculated"), str(exposure_risk or "").lower()), "Rating based on discovered exposure findings."],
    ]
    recommendations = risk.get("recommendations")
    if recommendations:
        rows.append(["Recommendations", _value_html(recommendations), "Suggestions produced by the security-risk calculation."])
    severity_counts = exposure_summary.get("severity_counts", {})
    severity_rows = []
    meanings = {
        "Critical": "Requires immediate review.", "High": "Should be reviewed promptly.",
        "Medium": "Review and address as appropriate.", "Low": "Lower-priority observation.",
        "Informational": "Context only; not necessarily a security issue.",
    }
    for severity in SEVERITY_ORDER:
        count = severity_counts.get(severity)
        if count is None:
            count = sum(1 for finding in findings if finding.get("severity") == severity)
        severity_rows.append([_badge(severity, severity.lower()), escape(str(count)), escape(meanings[severity])])
    body = _table(["Metric", "Result", "Explanation"], rows, "report-table risk-table")
    factors = risk.get("factors") if isinstance(risk.get("factors"), list) else []
    if factors:
        factor_rows = [[
            _value_html(item.get("factor"), "Observed condition"),
            escape(str(item.get("points", "Not scored"))),
            _value_html(item.get("confidence"), "Not assessed"),
            _value_html(item.get("evidence"), "No evidence returned"),
            _value_html(item.get("reason"), "No explanation returned"),
        ] for item in factors if isinstance(item, dict)]
        body += "<h3>Score Contributions</h3>" + _table(["Observed Condition", "Points", "Confidence", "Evidence", "Why It Contributes"], factor_rows, "report-table risk-factors-table")
    if risk.get("explanation"):
        body += f"<p>{_value_html(risk.get('explanation'))}</p>"
    body += "<h3>Finding Severity</h3>" + _table(["Severity", "Count", "Meaning"], severity_rows, "report-table severity-table")
    return _section("Risk Summary", body, "risk-summary")


def _render_report_links(payload: Dict[str, Any]) -> str:
    paths = payload.get("report_paths") if isinstance(payload.get("report_paths"), dict) else {}
    rows = []
    for key, label in (("json", "JSON report"), ("html", "HTML report")):
        raw_path = paths.get(key)
        if not raw_path:
            rows.append([escape(label), "Not available", "No report path was recorded."])
            continue
        filename = _display_path(raw_path, f"report.{key}")
        href = escape(quote(filename), quote=True)
        link = f"<a href='{href}'>{escape(filename)}</a>"
        rows.append([escape(label), link, "Open the generated report file in the same output folder."])
    return _section("Generated Reports", _table(["Report", "File", "Description"], rows, "report-table generated-reports-table"), "generated-reports")


def generate_html_report(payload: Dict[str, Any]) -> str:
    modules = payload.get("modules") if isinstance(payload.get("modules"), dict) else {}
    parsed = payload.get("normalized_target") if isinstance(payload.get("normalized_target"), dict) else {}
    exposure = payload.get("exposure") if isinstance(payload.get("exposure"), dict) else {}
    exposure_summary = exposure.get("summary") if isinstance(exposure.get("summary"), dict) else {}
    findings = exposure.get("findings") if isinstance(exposure.get("findings"), list) else []
    risk_summary = payload.get("risk_summary") if isinstance(payload.get("risk_summary"), dict) else {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}

    target_value = payload.get("target", "Unknown target")
    hostname_value = parsed.get("hostname", modules.get("dns", {}).get("hostname", "Unknown"))
    target = escape(_display_text(target_value, "Unknown target"))
    hostname = escape(_display_text(hostname_value, "Unknown"))
    scan_date = escape(_display_text(payload.get("timestamp"), "n/a"))
    duration = escape(_display_text(metadata.get("duration_seconds"), "n/a"))

    security_risk = risk_summary.get("security_risk")
    if security_risk is None:
        security_risk = payload.get("risk", {}).get("overall_rating")
    security_score = risk_summary.get("security_score")
    if security_score is None and payload.get("risk", {}).get("overall_score") is not None:
        security_score = f"{payload['risk']['overall_score']}/100"
    exposure_risk = risk_summary.get("exposure_risk", exposure_summary.get("overall_score"))
    total_exposed = exposure_summary.get("total_exposed_resources", risk_summary.get("exposed_resources"))
    summary_rows = [
        ["Target", _value_html(target_value, "Unknown target")],
        ["Hostname", _value_html(hostname_value, "Unknown")],
        ["Scan Date", _value_html(payload.get("timestamp"))],
        ["Scan Duration", _value_html(f"{metadata['duration_seconds']} seconds" if metadata.get("duration_seconds") is not None else None)],
        ["Security Risk", _badge(_display_text(security_risk, "Not calculated"), str(security_risk or "").lower())],
        ["Security Score", escape(_display_text(security_score, "Not calculated"))],
        ["Exposure Risk", _badge(_display_text(exposure_risk, "Not calculated"), str(exposure_risk or "").lower())],
        ["Exposed Resources", escape(_display_text(total_exposed, "Not reported"))],
    ]
    executive_summary = _section(
        "Executive Summary",
        _table(["Metric", "Result"], summary_rows, "report-table executive-table"),
        "executive-summary",
    )

    scope_methodology = _section(
        "Assessment Scope and Methodology",
        _table(["Item", "Details"], [
            ["Target", _value_html(target_value, "Unknown target")],
            ["Scope", "The submitted hostname and its normalized base URL; discovered paths are listed as references and are not requested by Exposure Intelligence."],
            ["Methodology", "Passive DNS, WHOIS, HTTP/TLS metadata, robots.txt, sitemap, technology indicators, and security-header checks. Findings reflect only evidence collected during this run."],
        ], "report-table scope-table"),
        "assessment-scope",
    )

    report_sections = [
        executive_summary,
        scope_methodology,
        _render_dns_section(modules.get("dns", {}), hostname_value),
        _render_ip_section(modules.get("ip", {})),
        _render_whois_section(modules.get("whois", {})),
        _render_http_section(modules.get("http", {})),
        _render_ssl_section(modules.get("ssl", {})),
        _render_security_headers(modules.get("security_headers", {})),
        _render_technology_section(modules.get("technology", {})),
        _render_robots_section(modules.get("robots", {})),
        _render_sitemap_section(modules.get("sitemap", {})),
        _render_exposure_intelligence(payload),
        _render_findings(findings),
        _render_risk(payload, findings),
        _render_report_links(payload),
        _section(
            "Limitations and Disclaimer",
            "<p>Results are point-in-time observations and do not establish exploitability, authorization, or the absence of vulnerabilities. Technology identification is not confirmation of a CVE. Missing or failed checks are unknown, not evidence of safety. Use this report only for systems you own or are explicitly authorized to assess.</p>",
            "limitations-disclaimer",
        ),
    ]

    sanitized_payload = _sanitize_payload(payload)
    raw_json = json.dumps(sanitized_payload, ensure_ascii=False, indent=2, default=str)

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>Web Reconnaissance Report</title>
    <style>
        :root {{
            --bg: #0f172a;
            --panel: #f8fafc;
            --panel-alt: #eef2ff;
            --text: #111827;
            --muted: #475569;
            --border: #cbd5e1;
            --danger: #d92d20;
            --warning: #f59e0b;
            --success: #16a34a;
            --cyan: #0ea5e9;
            --shadow: rgba(15, 23, 42, 0.12);
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            background: linear-gradient(180deg, #0b1220 0%, #111827 100%);
            color: var(--text);
        }}
        .report-shell {{
            max-width: 1220px;
            margin: 32px auto;
            padding: 24px;
        }}
        .header-bar {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 22px 24px;
            box-shadow: 0 12px 28px var(--shadow);
            margin-bottom: 20px;
        }}
        .header-title-row {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
        }}
        .scan-another-link {{
            display: inline-flex;
            align-items: center;
            gap: 9px;
            flex: 0 0 auto;
            padding: 10px 13px;
            border: 1px solid var(--danger);
            color: #fff;
            background: var(--danger);
            font-size: 0.9rem;
            font-weight: 700;
            text-decoration: none;
        }}
        .scan-another-link:hover {{ background: #b42318; text-decoration: none; }}
        h1 {{
            margin: 0 0 10px 0;
            color: #0f172a;
            font-size: clamp(1.8rem, 2vw, 2.6rem);
        }}
        .header-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            font-size: 0.95rem;
            color: var(--muted);
        }}
        .panel {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 22px;
            margin-bottom: 20px;
            box-shadow: 0 10px 22px var(--shadow);
        }}
        h2 {{
            margin: 0 0 16px 0;
            color: #0f172a;
            font-size: 1.35rem;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            table-layout: fixed;
        }}
        .report-table th, .report-table td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
            overflow-wrap: anywhere;
        }}
        .report-table th {{
            background: var(--panel-alt);
            color: var(--text);
            font-weight: 700;
        }}
        .report-table td {{
            background: #fff;
            color: var(--text);
        }}
        .report-table thead th {{ background: #e5eaf3; }}
        .report-table tbody tr:last-child td {{ border-bottom: 0; }}
        .executive-table th:first-child {{ width: 34%; }}
        .dns-summary th:first-child, .ip-table th:first-child {{ width: 25%; }}
        .dns-records th:nth-child(1) {{ width: 12%; }}
        .dns-records th:nth-child(2) {{ width: 16%; }}
        .dns-records th:nth-child(4) {{ width: 27%; }}
        .table-wrap {{ width: 100%; overflow-x: auto; margin-bottom: 14px; }}
        .exposure-intelligence-table {{ min-width: 1040px; }}
        .value-list > div + div {{ margin-top: 5px; }}
        .dns-records td:nth-child(3) {{ overflow-wrap: anywhere; word-break: break-word; }}
        .empty-cell {{ color: var(--muted); }}
        h3 {{ margin: 20px 0 12px; color: #0f172a; font-size: 1.08rem; }}
        .status-badge {{ white-space: nowrap; }}
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 999px;
            color: white;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.02em;
        }}
        .raw-box {{
            background: #111827;
            color: #e2e8f0;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 15px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
            font-family: "Consolas", "Courier New", monospace;
            font-size: 0.88rem;
        }}
        details {{
            background: white;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 0 14px;
        }}
        summary {{
            cursor: pointer;
            font-weight: 700;
            padding: 14px 0;
            color: #0f172a;
        }}
        a {{ color: #0f6cbd; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        @media (max-width: 640px) {{
            .report-shell {{ padding: 12px; }}
            .header-bar, .panel {{ padding: 16px; }}
            .report-table th, .report-table td {{ padding: 9px 10px; }}
            .header-title-row {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
    <div class='report-shell'>
        <header class='header-bar'>
            <div class='header-title-row'>
                <h1>Web Reconnaissance Report</h1>
                <a class='scan-another-link' href='/app/' id='scan-another-link' hidden>Scan another URL <span aria-hidden='true'>↗</span></a>
            </div>
            <div class='header-meta'>
                <span><strong>Target:</strong> {target}</span>
                <span><strong>Hostname:</strong> {hostname}</span>
                <span><strong>Scan Date:</strong> {scan_date}</span>
                <span><strong>Duration:</strong> {duration} seconds</span>
            </div>
        </header>

        {''.join(report_sections)}

        <section class='panel'>
            <details>
                <summary>View Raw Data</summary>
                <pre class='raw-box'>{escape(raw_json)}</pre>
            </details>
        </section>
    </div>
    <script>
        if (window.location.protocol === 'http:' || window.location.protocol === 'https:') {{
            document.getElementById('scan-another-link').hidden = false;
        }}
    </script>
</body>
</html>
"""
    return html
