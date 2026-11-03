from reporting.report_generator import _extract_exposure_candidates, generate_html_report


def _payload(robots="", sitemap_locations=(), http=None):
    locations = "".join(f"<url><loc>{location}</loc></url>" for location in sitemap_locations)
    return {
        "normalized_target": {"hostname": "example.com", "base_url": "https://example.com", "path": "/"},
        "modules": {
            "robots": {"status": "ok", "content": robots},
            "sitemap": {"status": "ok", "results": [{"status": "found", "content": f"<urlset>{locations}</urlset>"}]},
            "http": http or {},
        },
    }


def test_exposure_candidates_normalize_deduplicate_and_keep_sources():
    payload = _payload(
        robots="User-agent: *\nDisallow: /admin/\nAllow: /admin\nDisallow: /news//today/?from=map\n",
        sitemap_locations=(
            "https://example.com/admin",
            "https://example.com/news/today?from=map",
        ),
    )

    candidates = _extract_exposure_candidates(payload)

    assert [item["resource"] for item in candidates] == ["/admin", "/news/today?from=map"]
    assert candidates[0]["sources"] == ["robots.txt", "sitemap.xml"]
    assert len(candidates[0]["evidence"]) == 3
    assert all(item["category"] == "Publicly Referenced" for item in candidates)
    assert all(item["checked"] is False for item in candidates)


def test_exposure_candidates_skip_invalid_urls_and_flag_external_for_review():
    payload = _payload(
        robots="Disallow: /bad path\nDisallow: //evil.example/path\n",
        sitemap_locations=(
            "javascript:alert(1)",
            "https://bad host/path",
            "https://example.com/%ZZ",
            "https://other.example/private",
        ),
    )

    candidates = _extract_exposure_candidates(payload)

    assert len(candidates) == 1
    assert candidates[0]["resource"] == "https://other.example/private"
    assert candidates[0]["category"] == "Requires Review"
    assert candidates[0]["checked"] is False


def test_exposure_candidates_reuse_http_only_for_exact_matching_resource():
    payload = _payload(
        robots="Disallow: /\nDisallow: /admin\n",
        sitemap_locations=("https://example.com/",),
        http={
            "status": "ok", "status_code": 200, "final_url": "https://example.com/",
            "requested_url": "https://example.com/",
            "requested_resources": [{"url": "https://example.com/", "status_code": 200}],
            "content": "<a href='/admin'>Admin</a><script src='/assets/app.js'></script>",
        },
    )

    candidates = _extract_exposure_candidates(payload)

    root = next(item for item in candidates if item["resource"] == "/")
    admin = next(item for item in candidates if item["resource"] == "/admin")
    asset = next(item for item in candidates if item["resource"] == "/assets/app.js")
    assert root["resource"] == "/"
    assert root["http_status"] == 200
    assert root["category"] == "HTTP Response Observed"
    assert root["checked"] is True
    assert admin["http_status"] is None
    assert admin["category"] == "Publicly Referenced"
    assert admin["checked"] is False
    assert "HTML" in admin["sources"]
    assert asset["checked"] is False

    html = generate_html_report(payload)
    assert "HTTP response observed (200)" in html
    assert "Candidate URLs with an exact-request attempt" in html
    assert "<td>1</td>" in html
    assert "Additional candidate-path requests made" in html
    assert "/admin" in [item["resource"] for item in candidates]
    assert "Unique candidate URLs referenced" in html


def test_exposure_candidates_report_failed_existing_check_as_unknown():
    payload = _payload(
        robots="Disallow: /\n",
        http={
            "status": "error", "error": "connection timed out",
            "requested_url": "https://example.com/",
            "requested_resources": [{"url": "https://example.com/", "status_code": None}],
        },
    )

    candidate = _extract_exposure_candidates(payload)[0]

    assert candidate["checked"] is True
    assert candidate["http_status"] is None
    assert candidate["category"] == "Check Failed"
    html = generate_html_report(payload)
    assert "attempted this exact URL but did not receive a usable response" in html


def test_exposure_intelligence_empty_results_are_reported_as_zero():
    payload = {"modules": {}}

    candidates = _extract_exposure_candidates(payload)
    html = generate_html_report(payload)

    assert candidates == []
    assert "Exposure Intelligence" in html
    assert "Unique candidate URLs referenced" in html
    assert "Candidate URLs with an exact-request attempt" in html
    assert "<td>0</td>" in html
    section = html.split("id='exposure-intelligence'", 1)[1].split("</section>", 1)[0]
    assert "Not checked" not in section
