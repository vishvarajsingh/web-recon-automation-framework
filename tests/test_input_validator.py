from modules.input_validator import normalize_target


def test_normalize_target_domain():
    result = normalize_target("example.com")
    assert result["valid"] is True
    assert result["hostname"] == "example.com"


def test_normalize_target_rejects_bad_input():
    result = normalize_target("javascript:alert(1)")
    assert result["valid"] is False
