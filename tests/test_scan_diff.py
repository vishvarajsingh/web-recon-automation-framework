from backend.app.services.scan_diff import compare_reports
from reporting.comparison_report import generate_comparison_html


def report():
    return {
        "target": "example.com",
        "normalized_target": {"hostname": "example.com", "base_url": "https://example.com"},
        "modules": {
            "dns": {"status": "ok", "records": {
                name: {"status": "ok", "values": values}
                for name, values in {
                    "A": ["93.184.216.34"], "AAAA": [], "MX": ["mail.example.com"],
                    "NS": ["ns1.example.com"], "TXT": ["v=spf1 -all"], "CNAME": [],
                }.items()
            }},
            "http": {"status": "ok", "status_code": 200, "final_url": "https://example.com/", "redirect_chain": [], "cookies": {}, "cookie_attributes": {}},
            "security_headers": {"status": "ok", "headers": {
                "strict_transport_security": "max-age=31536000",
                "content_security_policy": "default-src 'self'",
                "x_frame_options": "DENY",
                "x_content_type_options": "nosniff",
                "referrer_policy": "strict-origin",
            }},
            "ssl": {"status": "ok", "issuer": "CN=CA", "subject": "CN=example.com", "valid_until": "2030-01-01", "days_remaining": 365, "san_entries": ["example.com"], "expired": False},
            "technology": {"status": "identified", "technologies": ["Nginx"]},
            "robots": {"status": "ok", "content": "Disallow: /admin\n"},
            "sitemap": {"status": "not_found", "results": [{"status": "not_found"}]},
        },
        "risk": {"overall_score": 10, "overall_rating": "Low", "evidence_status": "complete", "factors": []},
        "exposure": {"findings": []},
    }


def test_identical_reports_are_unchanged():
    result = compare_reports(report(), report())
    assert result["summary"]["unknown"] == 0
    assert result["summary"]["changed"] == 0
    assert result["summary"]["unchanged"] > 0


def test_dns_new_and_removed_record_values_are_classified():
    old, new = report(), report()
    old["modules"]["dns"]["records"]["A"]["values"] = ["192.0.2.1"]
    new["modules"]["dns"]["records"]["A"]["values"] = ["192.0.2.2"]
    old["modules"]["dns"]["records"]["TXT"]["values"] = ["old"]
    new["modules"]["dns"]["records"]["TXT"]["values"] = ["new"]

    result = compare_reports(old, new)
    dns = [item for item in result["changes"] if item["category"] == "DNS"]
    assert any(item["title"] == "A records changed" and item["change_type"] == "CHANGED" for item in dns)
    assert any(item["title"] == "TXT records changed" and item["change_type"] == "CHANGED" for item in dns)


def test_dns_record_type_appearing_and_disappearing_is_classified():
    old, new = report(), report()
    old["modules"]["dns"]["records"]["AAAA"] = {"status": "no_answer"}
    new["modules"]["dns"]["records"]["AAAA"] = {"status": "ok", "values": ["2001:db8::1"]}
    old["modules"]["dns"]["records"]["MX"] = {"status": "ok", "values": ["mail.example.com"]}
    new["modules"]["dns"]["records"]["MX"] = {"status": "no_answer"}
    result = compare_reports(old, new)
    assert any(item["title"] == "New AAAA records" and item["change_type"] == "NEW" for item in result["changes"])
    assert any(item["title"] == "MX records removed" and item["change_type"] == "REMOVED" for item in result["changes"])


def test_security_tls_technology_and_risk_changes_are_evidence_backed():
    old, new = report(), report()
    new["modules"]["security_headers"]["headers"]["content_security_policy"] = ""
    new["modules"]["ssl"].update({"issuer": "CN=New CA", "valid_until": "2031-01-01", "expired": True})
    new["modules"]["technology"]["technologies"] = ["Apache"]
    old["risk"].update({"overall_score": 10, "factors": []})
    new["risk"].update({"overall_score": 35, "factors": [{"factor": "Expired TLS certificate", "severity": "Medium", "confidence": "High"}]})

    result = compare_reports(old, new)
    assert any(item["change_type"] == "NEW" and "content_security_policy" in item["title"] for item in result["changes"])
    assert any(item["change_type"] == "CHANGED" and "issuer" in item["title"] for item in result["changes"])
    assert any(item["change_type"] == "NEW" and item["category"] == "Technology" for item in result["changes"])
    assert result["risk"]["delta"] == 25
    assert any(item["title"] == "Risk factor introduced: Expired TLS certificate" for item in result["changes"])


def test_http_cookie_values_and_security_attributes_are_compared():
    old, new = report(), report()
    old["modules"]["http"]["cookies"] = {"session": "old"}
    new["modules"]["http"]["cookies"] = {"session": "new"}
    old["modules"]["http"]["cookie_attributes"] = {"session": {"secure": False, "http_only": False, "same_site": None}}
    new["modules"]["http"]["cookie_attributes"] = {"session": {"secure": True, "http_only": True, "same_site": "Lax"}}
    result = compare_reports(old, new)
    assert any(item["category"] == "HTTP" and item["title"] == "HTTP: cookies" and item["change_type"] == "CHANGED" for item in result["changes"])
    assert any(item["category"] == "HTTP" and item["title"] == "HTTP: cookie_attributes" and item["change_type"] == "CHANGED" for item in result["changes"])


def test_failed_path_source_does_not_create_false_removal_or_resolution():
    old, new = report(), report()
    old["exposure"]["findings"] = [{"source": "robots.txt", "title": "Admin path", "resource": "/admin", "severity": "Medium"}]
    new["modules"]["robots"] = {"status": "failed", "error": "timeout"}
    new["exposure"]["findings"] = []

    result = compare_reports(old, new)
    assert any(item["category"] == "Exposure" and item["change_type"] == "UNKNOWN" for item in result["changes"])
    assert any(item["category"] == "Exposure Observations" and item["change_type"] == "UNKNOWN" for item in result["changes"])
    assert not any(item["change_type"] in {"REMOVED", "RESOLVED"} and item["category"].startswith("Exposure") for item in result["changes"])


def test_truncated_robots_source_is_unknown_for_candidate_removal_and_finding_resolution():
    old, new = report(), report()
    old["modules"]["robots"]["content"] = "Disallow: /admin\n"
    old["exposure"]["findings"] = [{"source": "robots.txt", "title": "Admin reference", "resource": "/admin"}]
    new["modules"]["robots"] = {"status": "ok", "content": "", "content_truncated": True}
    new["exposure"]["findings"] = []

    result = compare_reports(old, new)

    assert any(item["category"] == "Exposure" and item["change_type"] == "UNKNOWN" for item in result["changes"])
    assert any(item["category"] == "Exposure Observations" and item["change_type"] == "UNKNOWN" for item in result["changes"])
    assert not any(item["category"].startswith("Exposure") and item["change_type"] in {"REMOVED", "RESOLVED"} for item in result["changes"])


def test_truncated_sitemap_source_is_unknown_for_candidate_removal_and_finding_resolution():
    old, new = report(), report()
    old["modules"]["sitemap"] = {"status": "ok", "results": [{
        "status": "found", "content": "<urlset><url><loc>https://example.com/admin</loc></url></urlset>",
    }]}
    old["exposure"]["findings"] = [{"source": "sitemap.xml", "title": "Admin reference", "resource": "/admin"}]
    new["modules"]["sitemap"] = {"status": "ok", "results": [{
        "status": "found", "content": "<urlset />", "content_truncated": True,
    }]}
    new["exposure"]["findings"] = []

    result = compare_reports(old, new)

    assert any(item["category"] == "Exposure" and item["change_type"] == "UNKNOWN" for item in result["changes"])
    assert any(item["category"] == "Exposure Observations" and item["change_type"] == "UNKNOWN" for item in result["changes"])
    assert not any(item["category"].startswith("Exposure") and item["change_type"] in {"REMOVED", "RESOLVED"} for item in result["changes"])


def test_incomplete_technology_fingerprint_does_not_remove_previous_detection():
    old, new = report(), report()
    old["modules"]["technology"] = {"status": "identified", "technologies": ["WordPress"]}
    new["modules"]["technology"] = {"status": "incomplete", "technologies": []}

    result = compare_reports(old, new)

    assert any(item["category"] == "Technology" and item["change_type"] == "UNKNOWN" for item in result["changes"])
    assert not any(item["category"] == "Technology" and item["change_type"] == "REMOVED" for item in result["changes"])


def test_complete_exposure_source_can_resolve_a_previous_finding():
    old, new = report(), report()
    old["exposure"]["findings"] = [{"source": "robots.txt", "title": "Admin path", "resource": "/admin", "severity": "Medium"}]
    new["modules"]["robots"]["content"] = ""
    new["exposure"]["findings"] = []
    result = compare_reports(old, new)
    assert any(item["category"] == "Exposure Observations" and item["change_type"] == "RESOLVED" for item in result["changes"])


def test_failed_security_module_does_not_resolve_risk_factor_or_claim_score_delta():
    old, new = report(), report()
    old["risk"] = {"overall_score": 15, "overall_rating": "Low", "factors": [{"factor": "Missing Content-Security-Policy"}]}
    new["risk"] = {"overall_score": 0, "overall_rating": "Low", "factors": []}
    new["modules"]["security_headers"] = {"status": "failed", "error": "timeout"}
    result = compare_reports(old, new)
    assert result["risk"]["delta"] is None
    assert any(item["category"] == "Risk" and item["change_type"] == "UNKNOWN" for item in result["changes"])
    assert not any(item["category"] == "Risk" and item["change_type"] == "RESOLVED" for item in result["changes"])


def test_legacy_comparison_without_required_risk_fields_is_inconclusive():
    old, new = report(), report()
    old["risk"].pop("evidence_status")
    new["risk"].pop("evidence_status")
    new["modules"]["ssl"].pop("days_remaining")

    result = compare_reports(old, new)

    assert result["risk"]["delta"] is None
    assert result["risk"]["evidence_status"] == "incomplete"


def test_missing_dns_module_is_unknown_not_removed():
    old, new = report(), report()
    new["modules"].pop("dns")
    result = compare_reports(old, new)
    assert any(item["category"] == "DNS" and item["change_type"] == "UNKNOWN" for item in result["changes"])


def test_comparison_report_escapes_content_and_has_expandable_evidence():
    old, new = report(), report()
    new["target"] = "<example.com>"
    result = compare_reports(old, new)
    html = generate_comparison_html(result)
    assert "&lt;example.com&gt;" in html
    assert "<details><summary>Evidence</summary>" in html
    assert "Recommended Investigation Priorities" in html
    assert "C:\\Users\\" not in html
