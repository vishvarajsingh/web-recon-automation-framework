from types import SimpleNamespace

from modules import tech_detector
from reporting.report_generator import generate_html_report


class FakeCookie:
    name = "PHPSESSID"
    domain = "example.test"
    path = "/"
    secure = True
    _rest = {"SameSite": "Lax"}

    def has_nonstandard_attr(self, name):
        return name.lower() == "httponly"


class FakeResponse:
    def __init__(self, body, headers=None, cookies=None):
        self.body = body.encode()
        self.status_code = 200
        self.headers = headers or {}
        self.cookies = cookies or []
        self.url = "https://example.test/"
        self.encoding = "utf-8"

    def iter_content(self, chunk_size):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start:start + chunk_size]

    def close(self):
        pass


def test_technology_matches_passive_sources_with_evidence_and_confidence(monkeypatch):
    response = FakeResponse(
        '<meta name="generator" content="WordPress 6.5"><script src="/wp-content/app.js"></script>',
        headers={"Server": "nginx/1.27", "X-Powered-By": "PHP/8.3"},
        cookies=[FakeCookie()],
    )
    monkeypatch.setattr(tech_detector, "safe_get", lambda *args, **kwargs: response)

    result = tech_detector.detect_technology("https://example.test")

    assert result["status"] == "identified"
    detections = {item["name"]: item for item in result["detections"]}
    assert {"Nginx", "PHP", "WordPress"}.issubset(detections)
    assert all(item["confidence"] in {"Medium", "High"} for item in detections.values())
    assert any(item["source"] == "HTML meta generator" for item in detections["WordPress"]["evidence"])
    assert any(item["source"] == "Cookie name and attributes" for item in detections["PHP"]["evidence"])
    assert detections["PHP"]["confidence"] == "High"

    report = generate_html_report({"modules": {"technology": result}})
    assert "Technology Detection" in report
    assert "WordPress" in report
    assert "Supporting Evidence" in report
    assert "Cookie name and attributes" in report


def test_technology_does_not_match_broad_prose_substrings(monkeypatch):
    body = "The word express appears here, as do wordpress and nginx in ordinary documentation prose."
    monkeypatch.setattr(tech_detector, "safe_get", lambda *args, **kwargs: FakeResponse(body))

    result = tech_detector.detect_technology("https://example.test")

    assert result["status"] == "no_match"
    assert result["technologies"] == []
    assert result["complete"] is True


def test_truncated_technology_response_is_incomplete_even_with_matches(monkeypatch):
    monkeypatch.setattr(tech_detector, "safe_get", lambda *args, **kwargs: FakeResponse(""))
    monkeypatch.setattr(tech_detector, "read_response_text", lambda _response: ('<meta name="generator" content="Drupal">', True))

    result = tech_detector.detect_technology("https://example.test")

    assert result["status"] == "incomplete"
    assert result["complete"] is False
    assert result["technologies"] == ["Drupal"]


def test_technology_failure_is_distinct_from_no_match(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("offline fixture")

    monkeypatch.setattr(tech_detector, "safe_get", fail)

    result = tech_detector.detect_technology("https://example.test")

    assert result["status"] == "failed"
    assert result["complete"] is False
    assert result["technologies"] == []


def test_non_success_http_response_does_not_claim_complete_no_match(monkeypatch):
    response = FakeResponse("<html>Nothing useful</html>")
    response.status_code = 404
    monkeypatch.setattr(tech_detector, "safe_get", lambda *args, **kwargs: response)

    result = tech_detector.detect_technology("https://example.test")

    assert result["status"] == "incomplete"
    assert result["complete"] is False
    assert result["technologies"] == []
