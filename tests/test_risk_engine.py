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
        "security_headers": {"status": "ok", "headers": {
            "strict_transport_security": "", "content_security_policy": "", "x_frame_options": "",
        }},
        "ssl": {"status": "ok", "expired": True, "days_remaining": -1},
        "http": {"status": "ok", "status_code": 200},
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
        "reason": "Expired TLS certificate contributes 35 points to the deterministic observed risk-points total.",
    }]
    assert result["overall_rating"] == "Medium"
    assert result["evidence_status"] == "complete"
    assert "capped at 100" in result["explanation"]
    assert "higher points mean more observed risk" in result["score_meaning"]


def test_risk_engine_ignores_failed_or_invalid_status_evidence():
    result = RiskEngine().score({
        "security_headers": {"status": "error", "headers": {}, "error": "timeout"},
        "ssl": {"status": "error", "days_remaining": -1},
        "http": {"status": "ok", "status_code": 700},
    })

    assert result["overall_score"] == 0
    assert result["factors"] == []
    assert result["overall_rating"] == "Unknown"
    assert result["observed_risk_rating"] == "Low"
    assert result["evidence_status"] == "incomplete"


def test_zero_observed_risk_with_complete_evidence_is_low():
    result = RiskEngine().score({
        "security_headers": {"status": "ok", "headers": {
            "strict_transport_security": "max-age=31536000",
            "content_security_policy": "default-src 'self'",
            "x_frame_options": "DENY",
        }},
        "ssl": {"status": "ok", "expired": False, "days_remaining": 90},
        "http": {"status": "ok", "status_code": 200},
    })

    assert result["overall_score"] == 0
    assert result["overall_rating"] == "Low"
    assert result["evidence_status"] == "complete"


def test_missing_required_risk_fields_make_interpretation_unknown():
    result = RiskEngine().score({
        "security_headers": {"status": "ok", "headers": {"strict_transport_security": ""}},
        "ssl": {"status": "ok", "expired": False},
        "http": {"status": "ok", "status_code": 200},
    })

    assert result["overall_rating"] == "Unknown"
    assert result["evidence_status"] == "incomplete"
