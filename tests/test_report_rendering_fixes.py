import json

from reporting.report_generator import generate_html_report


def test_ipv6_report_sections_use_canonical_dns_aaaa_values_and_preserve_modules():
    payload = {
        "modules": {
            "dns": {"status": "ok", "records": {"AAAA": {"status": "ok", "values": ["2001:db8::1", "2001:db8::2"]}}},
            "ip": {"status": "ok", "ipv4": [], "ipv6": [], "reverse_dns": []},
        }
    }
    original_json = json.dumps(payload, sort_keys=True)

    html = generate_html_report(payload)
    dns_section = html.split("id='dns-information'", 1)[1].split("</section>", 1)[0]
    ip_section = html.split("id='ip-information'", 1)[1].split("</section>", 1)[0]

    assert "IPv6 Addresses Found" in dns_section and "<td>2</td>" in dns_section
    for address in ("2001:db8::1", "2001:db8::2"):
        assert address in dns_section
        assert address in ip_section
    assert "<td>IPv6 Addresses</td><td>None returned" not in ip_section
    assert json.dumps(payload, sort_keys=True) == original_json


def test_ipv6_report_does_not_turn_failed_or_missing_aaaa_into_empty_success():
    failed = generate_html_report({
        "modules": {
            "dns": {"status": "failed", "records": {"AAAA": {"status": "timeout"}}},
            "ip": {"status": "ok", "ipv6": [], "ipv4": [], "reverse_dns": []},
        }
    })
    missing = generate_html_report({"modules": {"dns": {"records": {}}, "ip": {"status": "ok", "ipv6": []}}})
    malformed = generate_html_report({"modules": {"dns": {"records": {"AAAA": {"status": "ok"}}}, "ip": {"status": "ok", "ipv6": []}}})

    assert "Unavailable" in failed.split("id='dns-information'", 1)[1].split("</section>", 1)[0]
    assert "DNS AAAA lookup failed; IPv6 addresses are unknown." in failed
    assert "Not checked" in missing.split("id='dns-information'", 1)[1].split("</section>", 1)[0]
    assert "DNS AAAA lookup not available; IPv6 addresses are unknown." in missing
    assert "IPv6 Addresses Found" in malformed and "Unavailable" in malformed.split("id='dns-information'", 1)[1].split("</section>", 1)[0]
    assert "DNS AAAA lookup returned no usable address data" in malformed


def test_exposure_metric_definitions_are_explicit_in_html():
    html = generate_html_report({
        "exposure": {"summary": {"unique_candidate_urls": 424, "heuristic_observations": 165}, "findings": []},
        "modules": {},
    })

    assert "normalized and deduplicated URLs" in html
    assert "deduplicated by (resource, severity, title)" in html
    assert "not verified resources, confirmed vulnerabilities, or confirmed misconfigurations" in html


def test_no_match_technology_uses_na_confidence_and_states_remain_distinct():
    no_match = generate_html_report({"modules": {"technology": {"status": "no_match", "technologies": [], "detections": []}}})
    incomplete = generate_html_report({"modules": {"technology": {"status": "incomplete", "technologies": [], "detections": []}}})
    failed = generate_html_report({"modules": {"technology": {"status": "failed", "technologies": [], "detections": [], "error": "fixture failure"}}})
    detected = generate_html_report({"modules": {"technology": {"status": "identified", "technologies": ["ExampleTech"], "detections": [{"name": "ExampleTech", "confidence": "Medium", "evidence": ["fixture"]}]}}})

    assert "No supported match" in no_match and "<td>N/A</td>" in no_match
    assert "Detection incomplete" in incomplete
    assert "Detection failed" in failed
    assert "ExampleTech" in detected and "Medium" in detected


def test_whois_expiration_html_collapses_duplicate_dates_and_keeps_raw_values():
    expiration_values = ["2030-06-07T00:00:00+00:00", "2030-06-07T12:30:00-04:00", "2031-01-02T00:00:00Z"]
    payload = {"modules": {"whois": {"status": "ok", "expiration_date": expiration_values}}}

    html = generate_html_report(payload)
    visible_html = html.split("<details>", 1)[0]
    raw_html = html.split("<details>", 1)[1]

    assert "2030-06-07, 2031-01-02" in visible_html
    assert "2030-06-07T00:00:00+00:00" not in visible_html
    for value in expiration_values:
        assert value in raw_html
    assert payload["modules"]["whois"]["expiration_date"] == expiration_values


def test_robots_summary_is_compact_and_full_content_remains_expandable_and_in_json():
    rules = ["User-agent: *", "Allow: /public", "Allow: /public", "Disallow: /private", "Sitemap: https://example.test/sitemap.xml", "Crawl-delay: 2"]
    rules.extend(f"Disallow: /section-{index}" for index in range(200))
    content = "\n".join(rules)
    payload = {"modules": {"robots": {"status": "ok", "url": "https://example.test/robots.txt", "content": content}}}

    html = generate_html_report(payload)
    robots_section = html.split("id='robots'", 1)[1].split("</section>", 1)[0]
    visible_robots = robots_section.split("<details", 1)[0]
    json_text = json.dumps(payload)

    assert "Directive Category" in visible_robots
    assert "Unique Paths" in visible_robots
    assert "Other directives" in visible_robots
    assert "Full robots.txt directive evidence" in robots_section
    assert "Disallow: /section-199" not in visible_robots
    assert "Disallow: /section-199" in robots_section.split("<details", 1)[1]
    assert "Disallow: /section-199" in json_text
    assert len(visible_robots.split("<tr>")) < 10
