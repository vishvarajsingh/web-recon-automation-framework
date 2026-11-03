"""Classify passively observed URL references and response indicators."""

import logging
import re
from typing import Any, Dict, List

from modules.exposure_candidates import extract_exposure_candidates

logger = logging.getLogger("web_recon")


def get_exposure_rating(findings: List[Dict[str, Any]]) -> str:
    """Aggregate observation severity into a deterministic observation rating."""
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
    """Analyze collected references and return heuristic observations, not confirmations."""

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
        status_resource: Any = None,
        confidence: str = "Low",
        timestamp: Any = None,
    ) -> None:
        findings.append(
            {
                "title": title,
                "description": reason,
                "resource": resource,
                "affected_asset": resource,
                "category": category,
                "severity": severity,
                "confidence": confidence,
                "source": source,
                "detection_method": source,
                "timestamp": timestamp,
                "status_code": status_code,
                "status_resource": status_resource,
                "evidence": evidence,
                "reason": reason,
                "potential_impact": reason,
                "recommendation": recommendation,
                "references": [],
                "classification": "heuristic_observation",
                "confirmed_misconfiguration": False,
                "confirmed_vulnerability": False,
            }
        )

    def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        modules = payload.get("modules", {})
        http = modules.get("http", {}) if isinstance(modules.get("http"), dict) else {}
        robots = modules.get("robots", {}) if isinstance(modules.get("robots"), dict) else {}
        sitemap = modules.get("sitemap", {}) if isinstance(modules.get("sitemap"), dict) else {}
        timestamp = payload.get("timestamp")

        robots_content = robots.get("content", "") if isinstance(robots, dict) else ""
        if robots_content:
            for match in re.finditer(r"(?:Disallow|Allow):\s*(/\S*)", robots_content, re.IGNORECASE):
                path = match.group(1).split()[0]
                self._add_finding(
                    findings,
                    title="Path Referenced in robots.txt",
                    resource=path,
                    category="Other",
                    severity="Informational",
                    source="robots.txt",
                    evidence=match.group(0),
                    reason="This robots.txt directive references a URL; crawler directives do not establish whether it is accessible or restricted.",
                    recommendation="Treat this as a URL reference only. Do not infer exposure or vulnerability without separate verification.",
                    status_code=None,
                    timestamp=timestamp,
                )

            for keyword, title, category, severity in [
                ("/admin", "Administrative Path Referenced", "Administrative Interface", "Informational"),
                ("/login", "Authentication Path Referenced", "Authentication Portal", "Informational"),
                ("/dashboard", "Dashboard Path Referenced", "Administrative Interface", "Informational"),
                ("/api", "API Path Referenced", "API Endpoint", "Informational"),
                ("/backup", "Backup Path Referenced", "Backup Resource", "Informational"),
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
                        reason="The path name is a heuristic hint only; robots.txt does not establish that the resource exists or is accessible.",
                        recommendation="Verify the resource and its access controls through an authorized, separately scoped review.",
                        status_code=None,
                        timestamp=timestamp,
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
                        title="Potentially Sensitive URL Referenced in Sitemap",
                        resource=url,
                        category=category,
                        severity="Informational",
                        source="sitemap.xml",
                        evidence=url,
                        reason="A sitemap URL matched a path-name heuristic; the reference alone does not establish sensitive content or an access-control issue.",
                        recommendation="Treat this as a URL reference only and verify the resource before drawing security conclusions.",
                        status_code=None,
                        timestamp=timestamp,
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
                status_resource=http.get("final_url") or http.get("requested_url"),
                confidence="Medium",
                timestamp=timestamp,
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
                status_resource=http.get("final_url") or http.get("requested_url"),
                confidence="Medium",
                timestamp=timestamp,
            )

        content = http.get("content", "") if isinstance(http, dict) else ""
        if content:
            if re.search(r"/login", content, re.IGNORECASE):
                self._add_finding(
                    findings,
                    title="Authentication Path Referenced in HTML",
                    resource="/login",
                    category="Authentication Portal",
                    severity="Informational",
                    source="HTML",
                    evidence="/login",
                    reason="The retrieved page text referenced a login-like path; the path was not requested or verified by this check.",
                    recommendation="Treat this as a reference only; do not infer an authentication weakness.",
                    status_code=None,
                    timestamp=timestamp,
                )
            if re.search(r"/admin", content, re.IGNORECASE):
                self._add_finding(
                    findings,
                    title="Administrative Path Referenced in HTML",
                    resource="/admin",
                    category="Administrative Interface",
                    severity="Informational",
                    source="HTML",
                    evidence="/admin",
                    reason="The retrieved page text referenced an administrative-like path; the path was not requested or verified by this check.",
                    recommendation="Treat this as a reference only; verify the resource before making security conclusions.",
                    status_code=None,
                    timestamp=timestamp,
                )
            if re.search(r"/api/|swagger|openapi", content, re.IGNORECASE):
                self._add_finding(
                    findings,
                    title="API Path Referenced in HTML",
                    resource="API documentation",
                    category="API Documentation",
                    severity="Informational",
                    source="HTML",
                    evidence="API path or documentation reference discovered in public content",
                    reason="The page contained an API-like path or documentation marker; this check did not establish access restrictions.",
                    recommendation="Treat this as a reference only and review whether the resource is intended to be public.",
                    status_code=None,
                    timestamp=timestamp,
                )
            if re.search(r"/\.git|\.env|config(\.php|\.json|\.yaml|\.yml)|backup(\.zip|\.tar|\.gz)", content, re.IGNORECASE):
                self._add_finding(
                    findings,
                    title="Potentially Sensitive File Path Referenced in HTML",
                    resource="Sensitive file reference",
                    category="Configuration Resource",
                    severity="Informational",
                    source="HTML",
                    evidence="Potentially sensitive file or path reference in public content",
                    reason="The page text matched a sensitive-file path heuristic; no file request or content verification was performed.",
                    recommendation="Treat this as a reference only; do not infer that a sensitive file is exposed.",
                    status_code=None,
                    confidence="Medium",
                    timestamp=timestamp,
                )

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for finding in findings:
            key = (finding.get("resource"), finding.get("severity"), finding.get("title"))
            if key not in seen:
                seen.add(key)
                deduped.append(finding)

        deduped.sort(key=lambda item: self._severity_order.get(item.get("severity"), 0), reverse=True)

        candidates = extract_exposure_candidates(payload)
        checked_candidates = [item for item in candidates if item["checked"]]
        response_candidates = [item for item in checked_candidates if item["http_status"] is not None]
        heuristic_observations = len(deduped)
        severity_counts = {
            severity: sum(1 for finding in deduped if finding.get("severity") == severity)
            for severity in ["Critical", "High", "Medium", "Low", "Informational"]
        }

        return {
            "findings": deduped,
            "summary": {
                "observation_rating": get_exposure_rating(deduped),
                "unique_candidate_urls": len(candidates),
                "heuristic_observations": heuristic_observations,
                "http_checked_candidate_urls": len(checked_candidates),
                "http_response_candidate_urls": len(response_candidates),
                "confirmed_misconfigurations": 0,
                "misconfiguration_assessment": "not_performed",
                "confirmed_vulnerabilities": 0,
                "vulnerability_assessment": "not_performed",
                "severity_counts": severity_counts,
                "severity_counts": severity_counts,
            },
        }
