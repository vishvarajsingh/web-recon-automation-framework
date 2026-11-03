import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import main


def test_parse_target_domain():
    parsed = main.normalize_target('example.com')
    assert parsed['valid'] is True
    assert parsed['hostname'] == 'example.com'


def test_run_creates_outputs(tmp_path, monkeypatch):
    target = 'example.com'
    monkeypatch.setattr(main, "gather_whois_info", lambda target: {"status": "not_found"})
    monkeypatch.setattr(main, "gather_dns_info", lambda target: {"status": "ok", "records": {"A": {"status": "ok", "values": ["203.0.113.10"]}}})
    monkeypatch.setattr(main, "gather_ip_info", lambda target: {"status": "ok", "ipv4": ["203.0.113.10"], "ipv6": [], "reverse_dns": []})
    monkeypatch.setattr(main, "gather_http_headers", lambda target: {"status": "ok", "status_code": 200, "final_url": "https://example.com/", "content": "", "cookies": {}, "redirect_chain": []})
    monkeypatch.setattr(main, "gather_ssl_info", lambda target: {"status": "not_https"})
    monkeypatch.setattr(main, "gather_robots", lambda target: {"status": "ok", "content": ""})
    monkeypatch.setattr(main, "gather_sitemap", lambda target: {"status": "not_found", "results": []})
    monkeypatch.setattr(main, "gather_security_headers", lambda target: {"status": "ok", "headers": {key: "" for key in (
        "strict_transport_security", "content_security_policy", "x_frame_options", "x_content_type_options", "referrer_policy")}})
    monkeypatch.setattr(main, "detect_technology", lambda target: {"status": "ok", "technologies": []})
    payload = main.collect_recon(target, output_dir=tmp_path)
    assert payload['normalized_target']['hostname'] == 'example.com'
    json.dumps(payload)
    assert Path(payload["report_paths"]["json"]).exists()
    assert Path(payload["report_paths"]["html"]).exists()


if __name__ == '__main__':
    test_parse_target_domain()
    with pytest.MonkeyPatch.context() as monkeypatch:
        test_run_creates_outputs(Path(tempfile.mkdtemp()), monkeypatch)
    print('Basic framework tests passed')
