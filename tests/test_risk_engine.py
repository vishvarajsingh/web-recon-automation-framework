import pytest

from modules.risk_engine import RiskEngine, get_risk_rating


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "Low"),
        (20, "Low"),
        (21, "Medium"),
        (40, "Medium"),
        (41, "High"),
        (70, "High"),
        (71, "Critical"),
        (100, "Critical"),
    ],
)
def test_get_risk_rating_thresholds(score, expected):
    assert get_risk_rating(score) == expected


def test_risk_engine_scoring():
    engine = RiskEngine()
    result = engine.score({
        "security_headers": {"headers": {"content_security_policy": ""}},
        "ssl": {"status": "ok", "expired": True},
        "http": {"server": "nginx"},
    })
    assert result["overall_rating"] == "Critical"


def test_risk_engine_explains_distinct_score_contributions():
    result = RiskEngine().score({
        "security_headers": {"status": "ok", "headers": {
            "strict_transport_security": "max-age=31536000",
            "content_security_policy": "default-src 'self'",
            "x_frame_options": "DENY",
        }},
        "ssl": {"status": "ok", "expired": True, "days_remaining": 0},
        "http": {"status": "ok", "status_code": 200},
    })

    assert result["overall_score"] == 35
    assert result["factors"] == [{
        "factor": "Expired TLS certificate",
        "points": 35,
        "severity": "Medium",
        "confidence": "High",
        "evidence": "TLS inspection reported expired=True.",
        "reason": "Expired TLS certificate contributes 35 points to the deterministic security score.",
    }]
    assert "capped at 100" in result["explanation"]


def test_risk_engine_ignores_failed_or_invalid_status_evidence():
    result = RiskEngine().score({
        "security_headers": {"status": "error", "headers": {}, "error": "timeout"},
        "ssl": {"status": "error", "days_remaining": -1},
        "http": {"status": "ok", "status_code": 700},
    })

    assert result["overall_score"] == 0
    assert result["factors"] == []
