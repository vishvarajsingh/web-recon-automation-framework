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
    assert result["summary"]["total_exposed_resources"] >= 4
    assert any(finding["resource"] == "/admin" for finding in result["findings"])
    assert result["summary"]["overall_score"] in {"Critical", "High", "Medium", "Low", "Informational"}
