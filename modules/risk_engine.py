"""Centralized scoring of passively observed risk points and evidence coverage."""

from typing import Any, Dict


def get_risk_rating(score: int) -> str:
    """Convert observed risk points (higher means more observed risk) to a rating."""
    if score >= 71:
        return "Critical"
    if score >= 41:
        return "High"
    if score >= 21:
        return "Medium"
    return "Low"


class RiskEngine:
    """Score observed risk points and report whether required evidence is complete."""

    def __init__(self) -> None:
        self._score = 0

    def score(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate a capped score and return the evidence behind each contribution."""
        self._score = 0
        factors = []

        def add_factor(name: str, points: int, evidence: str, confidence: str = "Medium") -> None:
            self._score += points
            factors.append({
                "factor": name,
                "points": points,
                "severity": get_risk_rating(points),
                "confidence": confidence,
                "evidence": evidence,
                "reason": f"{name} contributes {points} points to the deterministic observed risk-points total.",
            })

        security_headers = findings.get("security_headers", {})
        headers = security_headers.get("headers", {}) if isinstance(security_headers, dict) else {}
        headers_check_failed = isinstance(security_headers, dict) and security_headers.get("status") in {"error", "failed"}
        if isinstance(headers, dict) and "headers" in security_headers and not headers_check_failed:
            if not headers.get("strict_transport_security", ""):
                add_factor("Missing HSTS", 15, "No Strict-Transport-Security value was collected.")
            if not headers.get("content_security_policy", ""):
                add_factor("Missing Content-Security-Policy", 15, "No Content-Security-Policy value was collected.")
            if not headers.get("x_frame_options", ""):
                add_factor("Missing X-Frame-Options", 10, "No X-Frame-Options value was collected.")

        ssl = findings.get("ssl", {})
        if isinstance(ssl, dict) and ssl.get("status") == "ok" and ssl.get("expired"):
            add_factor("Expired TLS certificate", 35, f"TLS inspection reported expired={ssl.get('expired')}.", "High")
        elif isinstance(ssl, dict) and ssl.get("status") == "ok":
            try:
                days_remaining = int(ssl.get("days_remaining"))
            except (TypeError, ValueError):
                days_remaining = None
            if days_remaining is not None and 0 <= days_remaining < 30:
                add_factor("TLS certificate nearing expiry", 10, f"TLS inspection reported {days_remaining} days remaining.")

        http = findings.get("http", {})
        try:
            status_code = int(http.get("status_code")) if isinstance(http, dict) and http.get("status_code") is not None else None
        except (TypeError, ValueError):
            status_code = None
        if status_code is not None and 500 <= status_code <= 599:
            add_factor("Server error response", 10, f"HTTP response returned status {status_code}.")

        score = min(self._score, 100)
        # A numeric zero is still useful as the observed-points total, but it is
        # not an authoritative low-risk conclusion when any input check failed.
        statuses = {
            "security_headers": (security_headers.get("status") if isinstance(security_headers, dict) else None),
            "ssl": (ssl.get("status") if isinstance(ssl, dict) else None),
            "http": (http.get("status") if isinstance(http, dict) else None),
        }
        required_header_fields = {"strict_transport_security", "content_security_policy", "x_frame_options"}
        headers_complete = (
            statuses["security_headers"] == "ok"
            and isinstance(headers, dict)
            and required_header_fields.issubset(headers)
        )
        http_complete = False
        if statuses["http"] == "ok":
            try:
                http_code = int(http.get("status_code")) if isinstance(http, dict) else None
                http_complete = http_code is not None and 100 <= http_code <= 599
            except (TypeError, ValueError):
                http_complete = False
        ssl_complete = statuses["ssl"] == "not_https"
        if statuses["ssl"] == "ok" and isinstance(ssl, dict) and isinstance(ssl.get("expired"), bool):
            if ssl["expired"]:
                ssl_complete = True
            else:
                try:
                    ssl_complete = int(ssl.get("days_remaining")) >= 0
                except (TypeError, ValueError):
                    ssl_complete = False
        complete = headers_complete and http_complete and ssl_complete
        observed_rating = get_risk_rating(score)
        rating = observed_rating if complete else "Unknown"

        return {
            "overall_score": score,
            "overall_rating": rating,
            "observed_risk_rating": observed_rating,
            "evidence_status": "complete" if complete else "incomplete",
            "evidence_completeness": {
                "security_headers": {"status": statuses["security_headers"], "complete": headers_complete},
                "http": {"status": statuses["http"], "complete": http_complete},
                "ssl": {"status": statuses["ssl"], "complete": ssl_complete},
            },
            "score_out_of": "100",
            "confidence": "High" if complete and factors else "Medium" if complete else "Low",
            "factors": factors,
            "score_meaning": "Observed risk points; higher points mean more observed risk. This is not a security protection score or probability.",
            "explanation": "Observed risk points are the sum of distinct scored conditions, capped at 100. Missing or failed checks add no points and make the risk rating Unknown until evidence is complete.",
            "recommendations": [
                "Enable HSTS and a strong Content-Security-Policy.",
                "Renew any expiring TLS certificates promptly.",
                "Review server response headers for hardening opportunities.",
            ],
        }
