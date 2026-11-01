"""Centralized security risk scoring for passive reconnaissance findings."""

from typing import Any, Dict


def get_risk_rating(score: int) -> str:
    """Convert a numeric score into a deterministic risk rating."""
    if score >= 71:
        return "Critical"
    if score >= 41:
        return "High"
    if score >= 21:
        return "Medium"
    return "Low"


class RiskEngine:
    """Assign a severity rating to the collected evidence."""

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
                "reason": f"{name} contributes {points} points to the deterministic security score.",
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
        rating = get_risk_rating(score)

        return {
            "overall_score": score,
            "overall_rating": rating,
            "score_out_of": "100",
            "confidence": "High" if factors else "Medium",
            "factors": factors,
            "explanation": "Score is the sum of distinct observed checks, capped at 100. Missing or failed checks do not add points.",
            "recommendations": [
                "Enable HSTS and a strong Content-Security-Policy.",
                "Renew any expiring TLS certificates promptly.",
                "Review server response headers for hardening opportunities.",
            ],
        }
