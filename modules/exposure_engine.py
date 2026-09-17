"""Passive exposure detection for publicly exposed resources and misconfigurations."""

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger("web_recon")


def get_exposure_rating(findings: List[Dict[str, Any]]) -> str:
    """Aggregate exposure findings into a deterministic exposure risk rating."""
    if not findings:
        return "Informational"
    if any(finding.get("severity") == "Critical" for finding in findings):
        return "Critical"
    if any(finding.get("severity") == "High" for finding in findings):
        return "High"
    if any(finding.get("severity") == "Medium" for finding in findings):
        return "Medium"
    if any(finding.get("severity") == "Low" for finding in findings):
        return "Low"
    return "Informational"


class ExposureDetectionEngine:
    """Analyze passive reconnaissance data for exposure indicators."""

    def __init__(self) -> None:
        self._severity_order = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    def _add_finding(
        self,
        findings: List[Dict[str, Any]],
        *,
        title: str,
        resource: str,
        category: str,
        severity: str,
        source: str,
        evidence: str,
        reason: str,
        recommendation: str,
        status_code: Any = None,
    ) -> None:
        findings.append(
            {
                "title": title,
                "resource": resource,
                "category": category,
                "severity": severity,
                "source": source,
                "status_code": status_code,
                "evidence": evidence,
                "reason": reason,
                "recommendation": recommendation,
            }
        )

    def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        modules = payload.get("modules", {})
        http = modules.get("http", {}) if isinstance(modules.get("http"), dict) else {}
        robots = modules.get("robots", {}) if isinstance(modules.get("robots"), dict) else {}
        sitemap = modules.get("sitemap", {}) if isinstance(modules.get("sitemap"), dict) else {}

        robots_content = robots.get("content", "") if isinstance(robots, dict) else ""
        if robots_content:
            for match in re.finditer(r"(?:Disallow|Allow):\s*(/\S*)", robots_content, re.IGNORECASE):
                path = match.group(1).split()[0]
                self._add_finding(
                    findings,
                    title="Potentially Sensitive Path Referenced",
                    resource=path,
                    category="Other",
                    severity="Low",
                    source="robots.txt",
                    evidence=match.group(0),
                    reason="A path was publicly referenced in robots.txt and may warrant review for access controls.",
                    recommendation="Review whether the referenced path should remain publicly discoverable.",
                    status_code=None,
                )

            for keyword, title, category, severity in [
                ("/admin", "Administrative Interface Discovered", "Administrative Interface", "Medium"),
                ("/login", "Authentication Portal Discovered", "Authentication Portal", "Medium"),
                ("/dashboard", "Dashboard Resource Discovered", "Administrative Interface", "Medium"),
                ("/api", "API Endpoint Referenced", "API Endpoint", "Medium"),
                ("/backup", "Backup Resource Referenced", "Backup Resource", "Medium"),
            ]:
                if keyword in robots_content.lower():
                    self._add_finding(
                        findings,
                        title=title,
                        resource=keyword,
                        category=category,
                        severity=severity,
                        source="robots.txt",
                        evidence=keyword,
                        reason="A potentially sensitive path was publicly referenced in robots.txt.",
                        recommendation="Confirm access controls and authentication requirements for the referenced resource.",
                        status_code=None,
                    )

        for item in sitemap.get("results", []) if isinstance(sitemap, dict) else []:
            content = item.get("content", "") if isinstance(item, dict) else ""
            for match in re.finditer(r"https?://[^<\s]+", content):
                url = match.group(0)
                lower_url = url.lower()
                if any(token in lower_url for token in ["swagger", "openapi", "/api/", "/admin", "/login", "/backup", "/config", "/.git"]):
                    category = "API Documentation" if any(token in lower_url for token in ["swagger", "openapi"]) else "Other"
                    self._add_finding(
                        findings,
                        title="Sensitive Path Referenced in Sitemap",
                        resource=url,
                        category=category,
                        severity="Medium",
                        source="sitemap.xml",
                        evidence=url,
                        reason="A sitemap entry referenced a resource that may be sensitive or not intended for public discovery.",
                        recommendation="Review whether the referenced resource should remain public and restrict access if necessary.",
                        status_code=None,
                    )

        http_headers = http.get("headers", {}) if isinstance(http.get("headers"), dict) else {}
        server = http.get("server", "")
        status_code = http.get("status_code")
        if server:
            self._add_finding(
                findings,
                title="Server Technology Disclosure",
                resource="Server banner",
                category="Information Disclosure",
                severity="Low",
                source="HTTP Header",
                evidence=f"Server: {server}",
                reason="The response revealed server technology information through the HTTP headers.",
                recommendation="Minimize unnecessary server/version information where operationally appropriate.",
                status_code=status_code,
            )

        if any(header in http_headers for header in ["x-powered-by", "server"]):
            self._add_finding(
                findings,
                title="Technology Fingerprinting",
                resource="Response headers",
                category="Information Disclosure",
                severity="Low",
                source="HTTP Header",
                evidence=", ".join(f"{key}: {value}" for key, value in http_headers.items() if key in {"x-powered-by", "server"}),
                reason="Response headers revealed platform or framework details that can assist targeting.",
                recommendation="Remove unnecessary version-specific headers where possible.",
                status_code=status_code,
            )

        content = http.get("content", "") if isinstance(http, dict) else ""
        if content:
            if re.search(r"/login", content, re.IGNORECASE):
                self._add_finding(
                    findings,
                    title="Authentication Portal Discovered",
                    resource="/login",
                    category="Authentication Portal",
                    severity="Medium",
                    source="HTML",
                    evidence="/login",
                    reason="The retrieved page referenced a login path that is publicly visible in the document content.",
                    recommendation="Ensure the login interface enforces strong authentication and is restricted as appropriate.",
                    status_code=status_code,
                )
            if re.search(r"/admin", content, re.IGNORECASE):
                self._add_finding(
                    findings,
                    title="Administrative Interface Discovered",
                    resource="/admin",
                    category="Administrative Interface",
                    severity="Medium",
                    source="HTML",
                    evidence="/admin",
                    reason="The retrieved page referenced an administrative path in public content.",
                    recommendation="Restrict administrative access with strong authentication, authorization, and access controls.",
                    status_code=status_code,
                )
            if re.search(r"/api/|swagger|openapi", content, re.IGNORECASE):
                self._add_finding(
                    findings,
                    title="API Documentation Referenced",
                    resource="API documentation",
                    category="API Documentation",
                    severity="Medium",
                    source="HTML",
                    evidence="API path or documentation reference discovered in public content",
                    reason="Public content referenced API documentation or related endpoints.",
                    recommendation="Consider limiting public visibility of API documentation if it should not be broadly accessible.",
                    status_code=status_code,
                )
            if re.search(r"/\.git|\.env|config(\.php|\.json|\.yaml|\.yml)|backup(\.zip|\.tar|\.gz)", content, re.IGNORECASE):
                self._add_finding(
                    findings,
                    title="Potentially Sensitive File Referenced",
                    resource="Sensitive file reference",
                    category="Configuration Resource",
                    severity="High",
                    source="HTML",
                    evidence="Potentially sensitive file or path reference in public content",
                    reason="Public content referenced a file or path that may be sensitive if exposed.",
                    recommendation="Verify that any referenced configuration or backup files are not publicly accessible.",
                    status_code=status_code,
                )

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for finding in findings:
            key = (finding.get("resource"), finding.get("severity"), finding.get("title"))
            if key not in seen:
                seen.add(key)
                deduped.append(finding)

        deduped.sort(key=lambda item: self._severity_order.get(item.get("severity"), 0), reverse=True)

        total = len(deduped)
        critical = sum(1 for finding in deduped if finding.get("severity") == "Critical")
        medium = sum(1 for finding in deduped if finding.get("severity") == "Medium")
        low = sum(1 for finding in deduped if finding.get("severity") == "Low")
        severity_counts = {
            severity: sum(1 for finding in deduped if finding.get("severity") == severity)
            for severity in ["Critical", "High", "Medium", "Low", "Informational"]
        }

        return {
            "findings": deduped,
            "summary": {
                "overall_score": get_exposure_rating(deduped),
                "total_exposed_resources": total,
                "critical_findings": critical,
                "high_findings": severity_counts["High"],
                "medium_findings": medium,
                "low_findings": low,
                "severity_counts": severity_counts,
            },
        }
