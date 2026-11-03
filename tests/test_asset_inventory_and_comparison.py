from datetime import datetime
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core import config
from backend.app.core.migrations import initialize_schema
from backend.app.dependencies import get_db
from backend.app.main import app
from backend.app.models import Asset, Base, Investigation
from backend.app.services.asset_service import asset_history, list_assets
from backend.app.services.comparison_service import compare_investigations
from backend.app.services.investigation_service import create_investigation


@pytest.fixture
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = factory()
    yield session
    session.close()
    engine.dispose()


def stored_report(score=10):
    return {
        "target": "example.com",
        "modules": {
            "dns": {"status": "ok", "records": {"A": {"status": "ok", "values": ["192.0.2.1"]}}},
            "http": {"status": "ok", "status_code": 200, "final_url": "https://example.com/", "redirect_chain": [], "cookies": {}},
            "security_headers": {"status": "ok", "headers": {name: "set" for name in (
                "strict_transport_security", "content_security_policy", "x_frame_options", "x_content_type_options", "referrer_policy")}},
            "ssl": {"status": "ok", "issuer": "CA", "subject": "example.com", "valid_until": "2030-01-01", "san_entries": ["example.com"], "expired": False},
            "technology": {"status": "identified", "technologies": ["Nginx"]},
            "robots": {"status": "ok", "content": ""},
            "sitemap": {"status": "not_found", "results": [{"status": "not_found"}]},
        },
        "risk": {"overall_score": score, "overall_rating": "Low", "evidence_status": "complete", "factors": []},
        "exposure": {"findings": []},
    }


def test_target_variants_share_one_asset_and_history_paginates(db_session):
    older = create_investigation(db_session, "EXAMPLE.com")
    newer = create_investigation(db_session, "https://example.com/path")
    db_session.commit()

    assets, total = list_assets(db_session, limit=10)
    asset, history, history_total = asset_history(db_session, older.asset_id, skip=0, limit=1)

    assert total == 1
    assert assets[0][0].canonical_target == "example.com"
    assert assets[0][1] == 2
    assert older.asset_id == newer.asset_id
    assert history_total == 2
    assert history[0].id == newer.id
    assert asset.first_seen_at == older.created_at
    assert asset.last_seen_at == newer.created_at


def test_legacy_database_migration_preserves_scans_and_backfills_assets():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.begin() as connection:
        connection.execute(text("""CREATE TABLE investigations (
            id INTEGER PRIMARY KEY, target VARCHAR(255) NOT NULL, target_type VARCHAR(50) NOT NULL,
            status VARCHAR(50) NOT NULL, risk_score INTEGER, risk_rating VARCHAR(50),
            report_location VARCHAR(1024), html_report_location VARCHAR(1024), raw_output JSON,
            progress INTEGER NOT NULL DEFAULT 0, progress_message VARCHAR(255),
            created_at DATETIME, updated_at DATETIME)"""))
        connection.execute(text("INSERT INTO investigations (id,target,target_type,status,progress,created_at,updated_at) VALUES (1,'Example.com','domain','completed',100,'2026-01-01','2026-01-01')"))
        connection.execute(text("INSERT INTO investigations (id,target,target_type,status,progress,created_at,updated_at) VALUES (2,'https://example.com/path','url','completed',100,'2026-02-01','2026-02-01')"))

    initialize_schema(engine)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM investigations")).scalar_one() == 2
        assert connection.execute(text("SELECT COUNT(*) FROM assets")).scalar_one() == 1
        assert connection.execute(text("SELECT COUNT(asset_id) FROM investigations")).scalar_one() == 2
        assert "risk_evidence_status" in {row[1] for row in connection.execute(text("PRAGMA table_info(investigations)"))}
    engine.dispose()


def test_comparison_rejects_unrelated_and_incomplete_scans(db_session):
    first = create_investigation(db_session, "example.com")
    other = create_investigation(db_session, "other.example")
    first.status = other.status = "completed"
    first.raw_output = other.raw_output = stored_report()
    db_session.commit()
    with pytest.raises(HTTPException) as unrelated_error:
        compare_investigations(db_session, first.id, other.id)
    assert "same normalized target" in unrelated_error.value.detail

    pending = create_investigation(db_session, "example.com")
    with pytest.raises(HTTPException) as pending_error:
        compare_investigations(db_session, first.id, pending.id)
    assert "Only completed" in pending_error.value.detail


@pytest.fixture
def api_client(monkeypatch, tmp_path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db
    app.state.asset_test_session_factory = factory
    monkeypatch.setattr(config.settings, "API_KEY", "asset-test-key")
    monkeypatch.setattr(config.settings, "OUTPUT_DIR", Path(tmp_path))
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()


def test_asset_history_and_comparison_api(api_client):
    session = api_client.app.state.asset_test_session_factory()
    previous = create_investigation(session, "Example.com")
    current = create_investigation(session, "https://example.com/path")
    previous.status = current.status = "completed"
    previous.raw_output = stored_report()
    current.raw_output = stored_report(20)
    session.commit()
    asset_id = current.asset_id
    previous_id, current_id = previous.id, current.id
    session.close()

    assets = api_client.get("/web-api/assets")
    history = api_client.get(f"/web-api/assets/{asset_id}/investigations?skip=0&limit=1")
    comparison = api_client.post("/web-api/investigations/compare", json={"previous_id": previous_id, "current_id": current_id})
    html = api_client.get(f"/web-api/investigations/{previous_id}/compare/{current_id}/report")
    invalid = api_client.post("/web-api/investigations/compare", json={"previous_id": 0, "current_id": current_id})

    assert assets.status_code == 200 and assets.json()["total"] == 1
    assert history.status_code == 200 and history.json()["total"] == 2 and len(history.json()["items"]) == 1
    assert comparison.status_code == 200 and comparison.json()["risk"]["delta"] == 10
    assert html.status_code == 200 and "Scan Comparison" in html.text
    assert invalid.status_code == 422
    assert api_client.get("/web-api/assets/999/investigations").status_code == 404
    page = api_client.get("/app/")
    assert "Asset inventory &amp; scan history" in page.text
    assert "Compare scans" in page.text
