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
        """Calculate an overall security risk score based on observed issues."""
        self._score = 0

        security_headers = findings.get("security_headers", {})
        headers = security_headers.get("headers", {}) if isinstance(security_headers, dict) else {}
        if not headers.get("strict_transport_security", ""):
            self._score += 15
        if not headers.get("content_security_policy", ""):
            self._score += 15
        if not headers.get("x_frame_options", ""):
            self._score += 10

        ssl = findings.get("ssl", {})
        if isinstance(ssl, dict) and ssl.get("status") == "ok" and ssl.get("expired"):
            self._score += 35
        if isinstance(ssl, dict) and ssl.get("status") == "ok" and ssl.get("days_remaining", 0) < 30:
            self._score += 10

        http = findings.get("http", {})
        if isinstance(http, dict) and http.get("status_code") and http.get("status_code") >= 500:
            self._score += 10

        score = min(self._score, 100)
        rating = get_risk_rating(score)

        return {
            "overall_score": score,
            "overall_rating": rating,
            "score_out_of": "100",
            "recommendations": [
                "Enable HSTS and a strong Content-Security-Policy.",
                "Renew any expiring TLS certificates promptly.",
                "Review server response headers for hardening opportunities.",
            ],
        }
