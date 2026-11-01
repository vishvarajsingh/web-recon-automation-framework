import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import requests

import main
from modules import http_headers, ssl_info
from modules.exposure_engine import ExposureDetectionEngine
from reporting.report_generator import generate_html_report


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


def test_generate_html_report_uses_professional_summary_and_no_raw_windows_paths():
    payload = {
        "target": "example.com",
        "timestamp": "2026-01-01T00:00:00Z",
        "normalized_target": {"hostname": "example.com", "scheme": "https", "base_url": "https://example.com", "path": "/"},
        "metadata": {"duration_seconds": 12.5},
        "risk_summary": {
            "security_risk": "Low",
            "security_score": "15/100",
            "exposure_risk": "Medium",
            "exposed_resources": 1,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 1,
            "low_findings": 0,
        },
        "risk": {"overall_score": 15, "overall_rating": "Low"},
        "exposure": {
            "summary": {
                "overall_score": "Medium",
                "total_exposed_resources": 1,
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 1,
                "low_findings": 0,
            },
            "findings": [{
                "title": "Administrative Interface Discovered",
                "severity": "Medium",
                "resource": "/admin",
                "source": "robots.txt",
                "status_code": 200,
                "evidence": "Disallow: /admin",
                "reason": "A public path hint may lead to a restricted administrative area.",
                "recommendation": "Verify access controls and authentication.",
            }],
        },
        "report_paths": {
            "json": "/tmp/example.json",
            "html": "/tmp/example.html",
        },
        "modules": {
            "whois": {"status": "ok", "domain_name": "example.com"},
            "dns": {"status": "not_found", "records": {"A": {"status": "nxdomain"}}},
            "http": {"status": "ok", "status_code": 200, "final_url": "https://example.com", "server": "ExampleServer", "content_type": "text/html"},
            "security_headers": {"status": "ok", "headers": {"strict_transport_security": "", "content_security_policy": "", "x_frame_options": "SAMEORIGIN", "x_content_type_options": "nosniff", "referrer_policy": "same-origin"}},
            "technology": {"status": "ok", "technologies": ["Apache"]},
            "robots": {"status": "ok", "results": ["Disallow: /admin"]},
            "sitemap": {"status": "not_found", "results": []},
        },
    }

    html = generate_html_report(payload)

    assert "Metric" in html and "Value" in html
    assert "Security Score" in html and "15/100" in html
    assert "Executive Summary" in html
    assert "Exposure Findings" in html
    assert "Administrative Interface Discovered" in html
    assert "View Raw Data" in html
    assert "example.json" in html and "example.html" in html
    assert "C:\\Users" not in html
    assert "absolute" not in html.lower()


def test_generate_html_report_formats_dns_and_ip_values_for_beginners():
    payload = {
        "target": "https://example.com",
        "normalized_target": {"hostname": "example.com"},
        "modules": {
            "dns": {
                "status": "partial",
                "hostname": "example.com",
                "records": {
                    "A": {"status": "ok", "values": ["192.0.2.10", "192.0.2.11"]},
                    "AAAA": {"status": "ok", "values": ["2001:db8::10", "2001:db8::11"]},
                    "MX": {"status": "no_answer"},
                    "NS": {"status": "no_answer"},
                    "TXT": {"status": "ok", "values": ["verification-token-" + "x" * 160]},
                    "CNAME": {"status": "no_answer"},
                },
            },
            "ip": {
                "status": "ok",
                "ipv4": ["192.0.2.10", "192.0.2.11"],
                "ipv6": ["2001:db8::10", "2001:db8::11"],
                "reverse_dns": ["host-a.example.net", "host-b.example.net"],
            },
        },
    }

    html = generate_html_report(payload)

    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        assert f">{record_type}</td>" in html
    assert "Target Hostname" in html and "example.com" in html
    assert "192.0.2.10" in html and "192.0.2.11" in html
    assert "2001:db8::10" in html and "2001:db8::11" in html
    assert "host-a.example.net" in html and "host-b.example.net" in html
    assert "No Answer" in html and "Found" in html
    assert "Points a hostname to an IPv6 address." in html
    assert "This does not prove server ownership or identity." in html
    assert "overflow-wrap: anywhere" in html


def test_generate_html_report_distinguishes_empty_failed_and_unchecked_dns():
    failed_html = generate_html_report({
        "normalized_target": {"hostname": "failure.example"},
        "modules": {
            "dns": {
                "status": "failed",
                "hostname": "failure.example",
                "records": {
                    "A": {"status": "timeout"},
                    "AAAA": {"status": "nxdomain"},
                },
            },
            "ip": {"status": "error", "error": "resolution timed out"},
        },
    })
    assert "Lookup failed; record existence is unknown." in failed_html
    assert "The DNS lookup returned NXDOMAIN; no record values were returned." in failed_html
    assert ">Failed</span>" in failed_html
    assert "The DNS lookup reported that the hostname does not exist." not in failed_html
    assert "Lookup failed; addresses are unknown." in failed_html
    assert "Not Checked" in failed_html

    empty_html = generate_html_report({
        "normalized_target": {"hostname": "empty.example"},
        "modules": {
            "dns": {
                "status": "not_found",
                "hostname": "empty.example",
                "records": {record_type: {"status": "no_answer"} for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")},
            },
            "ip": {"status": "ok", "ipv4": [], "ipv6": [], "reverse_dns": []},
        },
    })
    assert "No answer received" in empty_html
    assert "None returned" in empty_html
    assert "Unavailable" in empty_html
    assert "<td>0</td>" in empty_html


def test_generate_html_report_uses_specialized_module_tables_and_collapsed_raw_data():
    payload = {
        "target": "example.com",
        "normalized_target": {"hostname": "example.com"},
        "modules": {
            "whois": {"status": "ok", "registrar": "Example Registrar"},
            "dns": {"status": "ok", "hostname": "example.com", "records": {}},
            "ip": {"status": "ok", "ipv4": [], "ipv6": [], "reverse_dns": []},
            "http": {"status": "ok", "status_code": 200, "final_url": "https://example.com", "content": "RAW_HTTP_BODY_SENTINEL"},
            "ssl": {"status": "not_https"},
            "security_headers": {"status": "ok", "headers": {"x_frame_options": "DENY"}},
            "technology": {"status": "ok", "technologies": ["Apache"]},
            "robots": {"status": "ok", "url": "https://example.com/robots.txt", "content": "User-agent: *\nDisallow: /private"},
            "sitemap": {"status": "not_found", "results": [{"url": "https://example.com/sitemap.xml", "status": "not_found"}]},
        },
        "exposure": {"findings": [{"title": "Test finding", "severity": "Low", "resource": "/private", "evidence": "Disallow: /private", "recommendation": "Review access controls."}]},
        "risk": {"overall_rating": "Low", "overall_score": 12, "recommendations": ["Review response headers."]},
        "report_paths": {"json": "C:\\reports\\example.json", "html": "C:\\reports\\example.html"},
    }

    html = generate_html_report(payload)
    visible_report = html.split("<details>", 1)[0]

    for section in (
        "WHOIS Information", "DNS Summary", "IP Address Information", "HTTP Response",
        "SSL/TLS Certificate", "Security Headers", "Technology Detection", "robots.txt",
        "sitemap.xml", "Exposure Findings", "Risk Summary", "Generated Reports",
    ):
        assert section in visible_report
    assert "Security Header" in visible_report and "Observed Value" in visible_report
    assert "Finding</th>" in visible_report and "Recommended Action" in visible_report
    assert "Example Registrar" in visible_report and "Apache" in visible_report
    assert "RAW_HTTP_BODY_SENTINEL" not in visible_report
    assert "RAW_HTTP_BODY_SENTINEL" in html.split("<details>", 1)[1]
    assert "<details open" not in html
    assert "<td>{'status':" not in visible_report
    assert "href='example.json'" in visible_report
    assert "id='scan-another-link'" in html
    assert "href='/app/'" in html
    assert "Scan another URL" in html
    assert "C:\\reports" not in visible_report