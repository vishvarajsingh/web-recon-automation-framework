import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import requests

import main
from modules import http_headers, ssl_info
from modules.exposure_engine import ExposureDetectionEngine


class FakeHttpResponse:
    def __init__(self, content=b"<a href='/admin'>admin</a>", url="https://example.com"):
        self.status_code = 200
        self.url = url
        self.encoding = "utf-8"
        self.headers = {"server": "ExampleServer"}
        self.cookies = {}
        self.history = []
        self.elapsed = SimpleNamespace(total_seconds=lambda: 0.01)
        self._content = content

    def iter_content(self, chunk_size):
        for index in range(0, len(self._content), chunk_size):
            yield self._content[index:index + chunk_size]

    def close(self):
        pass


def test_http_content_flows_into_exposure_detection(monkeypatch):
    monkeypatch.setattr(http_headers.requests, "get", lambda *args, **kwargs: FakeHttpResponse())

    result = http_headers.gather_http_headers("https://example.com")
    exposure = ExposureDetectionEngine().analyze({"modules": {"http": result}})

    assert result["status"] == "ok"
    assert "/admin" in result["content"]
    assert any(finding["resource"] == "/admin" for finding in exposure["findings"])


def test_http_content_is_bounded(monkeypatch):
    response = FakeHttpResponse(b"x" * (http_headers.MAX_RESPONSE_CONTENT_BYTES + 10))
    monkeypatch.setattr(http_headers.requests, "get", lambda *args, **kwargs: response)

    result = http_headers.gather_http_headers("https://example.com")

    assert len(result["content"].encode("utf-8")) <= http_headers.MAX_RESPONSE_CONTENT_BYTES
    assert result["content_truncated"] is True


def test_ssl_success_uses_verified_tls_socket(monkeypatch):
    now = datetime.now(timezone.utc)

    class FakeCertificate:
        not_valid_before_utc = now - timedelta(days=1)
        not_valid_after_utc = now + timedelta(days=90)
        subject = SimpleNamespace(rfc4514_string=lambda: "CN=example.com")
        issuer = SimpleNamespace(rfc4514_string=lambda: "CN=Example CA")
        signature_algorithm_oid = SimpleNamespace(_name="sha256WithRSAEncryption")
        extensions = SimpleNamespace(
            get_extension_for_class=lambda certificate_type: SimpleNamespace(
                value=SimpleNamespace(get_values_for_type=lambda value_type: ["example.com"])
            )
        )

    class FakeTlsSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def getpeercert(self, binary_form=False):
            assert binary_form is True
            return b"certificate"

    class FakeContext:
        def wrap_socket(self, connection, server_hostname):
            assert server_hostname == "example.com"
            return FakeTlsSocket()

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(
        ssl_info.requests,
        "get",
        lambda *args, **kwargs: SimpleNamespace(
            status_code=200,
            headers={},
            url="https://example.com",
            close=lambda: None,
        ),
    )
    monkeypatch.setattr(ssl_info.socket, "create_connection", lambda *args, **kwargs: FakeConnection())
    monkeypatch.setattr(ssl_info.ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(ssl_info.x509, "load_der_x509_certificate", lambda value: FakeCertificate())

    result = ssl_info.gather_ssl_info("https://example.com")

    assert result["status"] == "ok"
    assert result["subject"] == "CN=example.com"
    assert result["san_entries"] == ["example.com"]


def test_ssl_failure_is_structured(monkeypatch):
    def fail_request(*args, **kwargs):
        raise requests.RequestException("connection failed")

    monkeypatch.setattr(ssl_info.requests, "get", fail_request)

    result = ssl_info.gather_ssl_info("https://example.com")

    assert result["status"] == "error"
    assert "connection failed" in result["error"]


def test_collect_recon_statuses_counts_and_saved_payload(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "gather_whois_info", lambda target: {"status": "ok"})
    monkeypatch.setattr(main, "gather_dns_info", lambda target: {"status": "not_found", "records": {}})
    monkeypatch.setattr(main, "gather_ip_info", lambda target: {"status": "ok", "ipv4": ["203.0.113.10"], "ipv6": [], "reverse_dns": []})
    monkeypatch.setattr(main, "gather_http_headers", lambda target: {
        "status": "ok",
        "status_code": 200,
        "server": "ExampleServer",
        "headers": {},
        "content": "<a href='/admin'>admin</a><a href='/.env'>config</a>",
    })
    monkeypatch.setattr(main, "gather_ssl_info", lambda target: {"status": "error", "error": "test failure"})
    monkeypatch.setattr(main, "gather_robots", lambda target: {"status": "not_found"})
    monkeypatch.setattr(main, "gather_sitemap", lambda target: {"status": "not_found", "results": []})
    monkeypatch.setattr(main, "gather_security_headers", lambda target: {"status": "ok", "headers": {}})
    monkeypatch.setattr(main, "detect_technology", lambda target: {"status": "ok", "technologies": []})

    payload = main.collect_recon("example.com", output_dir=tmp_path)
    saved = json.loads((tmp_path / next(path.name for path in tmp_path.glob("*.json"))).read_text())

    assert payload["metadata"]["resolved_ip"] == "203.0.113.10"
    assert payload["module_status"]["dns"] == "NOT_FOUND"
    assert payload["module_status"]["sitemap"] == "NOT_FOUND"
    assert payload["module_status"]["ssl"] == "FAILED"
    assert payload["risk_summary"]["high_findings"] == 1
    assert saved["report_paths"] == payload["report_paths"]