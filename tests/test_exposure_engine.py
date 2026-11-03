import pytest

from modules.exposure_engine import ExposureDetectionEngine, get_exposure_rating


@pytest.mark.parametrize(
    ("findings", "expected"),
    [
        ([{"severity": "Low"}], "Low"),
        ([{"severity": "Medium"}], "Medium"),
        ([{"severity": "Medium"}, {"severity": "Low"}], "Medium"),
        ([{"severity": "High"}, {"severity": "Low"}], "High"),
        ([{"severity": "Critical"}, {"severity": "Low"}], "Critical"),
    ],
)
def test_get_exposure_rating(findings, expected):
    assert get_exposure_rating(findings) == expected


def test_exposure_engine_detects_sensitive_paths():
    engine = ExposureDetectionEngine()
    payload = {
        "target": "https://example.com",
        "normalized_target": {"hostname": "example.com", "scheme": "https", "base_url": "https://example.com"},
        "modules": {
            "robots": {
                "status": "ok",
                "content": "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n",
            },
            "sitemap": {
                "results": [
                    {
                        "url": "https://example.com/sitemap.xml",
                        "status": "found",
                        "content": "<urlset><url><loc>https://example.com/swagger.json</loc></url></urlset>",
                    }
                ]
            },
            "http": {
                "status": "ok",
                "server": "nginx/1.18",
                "headers": {"x-powered-by": "PHP/8.2"},
                "content": "<a href='/login'>Login</a><script>const api='/api/v1/users'</script>",
            },
        },
    }

    result = engine.analyze(payload)
    assert result["summary"]["unique_candidate_urls"] >= 4
    assert result["summary"]["heuristic_observations"] == len(result["findings"])
    assert result["summary"]["http_checked_candidate_urls"] == 0
    assert result["summary"]["confirmed_misconfigurations"] == 0
    assert result["summary"]["confirmed_vulnerabilities"] == 0
    assert any(finding["resource"] == "/admin" for finding in result["findings"])
    admin_findings = [finding for finding in result["findings"] if finding["resource"] == "/admin"]
    assert all(finding["severity"] == "Informational" for finding in admin_findings)
    assert all(finding["confirmed_vulnerability"] is False for finding in admin_findings)
    assert result["summary"]["observation_rating"] in {"Critical", "High", "Medium", "Low", "Informational"}


def test_candidate_url_count_is_unique_when_multiple_heuristics_match_same_path():
    result = ExposureDetectionEngine().analyze({
        "normalized_target": {"base_url": "https://example.com"},
        "modules": {
            "robots": {"status": "ok", "content": "Disallow: /admin\n"},
            "sitemap": {"status": "ok", "results": [{
                "status": "found", "content": "<urlset><url><loc>https://example.com/admin</loc></url></urlset>",
            }]},
            "http": {"status": "ok", "content": "<a href='/admin'>Admin</a>"},
        },
    })

    assert result["summary"]["unique_candidate_urls"] == 1
    assert result["summary"]["heuristic_observations"] > 1
    assert result["summary"]["http_checked_candidate_urls"] == 0
