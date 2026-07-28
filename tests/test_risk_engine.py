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
