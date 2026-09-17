from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core import config
from backend.app.dependencies import get_db
from backend.app.main import app, database_health
from backend.app.models import Base
from backend.app.services.target_security import validate_target
from modules import network_policy


@pytest.fixture
def backend_client(monkeypatch, tmp_path):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.test_session_factory = session_factory
    monkeypatch.setattr(config.settings, "API_KEY", "test-key")
    monkeypatch.setattr(config.settings, "OUTPUT_DIR", Path(tmp_path))
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def public_dns(*args, **kwargs):
    return [(0, 0, 0, "", ("93.184.216.34", 0))]


def test_database_configuration_and_health(monkeypatch):
    assert config.settings.DATABASE_URL
    assert database_health()["status"] == "ok"

    class BrokenConnection:
        def __enter__(self):
            raise SQLAlchemyError("database down")

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("backend.app.main.engine.connect", lambda: BrokenConnection())
    assert database_health() == {"status": "error", "database": "unavailable"}


def test_dashboard_returns_database_unavailable(backend_client, monkeypatch):
    class BrokenSession:
        def query(self, *args, **kwargs):
            raise SQLAlchemyError("database down")

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr("backend.app.dependencies.SessionLocal", lambda: BrokenSession())
    backend_client.app.dependency_overrides.pop(get_db, None)

    response = backend_client.get("/api/dashboard/", headers={"X-API-Key": "test-key"})

    assert response.status_code == 503
    assert response.json()["detail"] == "Database unavailable"


def test_scan_routes_require_api_key(backend_client, monkeypatch):
    monkeypatch.setattr("backend.app.api.investigations.validate_target", lambda target: target)

    assert backend_client.get("/api/investigations/").status_code == 401
    assert backend_client.get("/api/investigations/", headers={"X-API-Key": "test-key"}).status_code == 200


def test_target_security_blocks_private_addresses(monkeypatch):
    monkeypatch.setattr("backend.app.services.target_security.socket.getaddrinfo", lambda *args, **kwargs: [
        (0, 0, 0, "", ("127.0.0.1", 443))
    ])

    with pytest.raises(ValueError, match="Private"):
        validate_target("http://127.0.0.1")


def test_redirect_security_blocks_private_destination(monkeypatch):
    class RedirectResponse:
        status_code = 302
        headers = {"Location": "http://127.0.0.1/admin"}

        def close(self):
            pass

    def resolve(host, *args, **kwargs):
        if host == "127.0.0.1":
            return [(0, 0, 0, "", ("127.0.0.1", 0))]
        return public_dns()

    monkeypatch.setattr(network_policy.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(network_policy.requests, "get", lambda *args, **kwargs: RedirectResponse())

    with pytest.raises(ValueError, match="Private"):
        network_policy.safe_get("https://example.com", timeout=1)


def test_cors_uses_configured_origins():
    cors = next(middleware for middleware in app.user_middleware if middleware.cls.__name__ == "CORSMiddleware")
    assert cors.kwargs["allow_origins"] == ["http://localhost:3000"]
    assert cors.kwargs["allow_credentials"] is False


def test_backend_executes_and_retrieves_recon_report(backend_client, monkeypatch, tmp_path):
    monkeypatch.setattr("backend.app.services.target_security.socket.getaddrinfo", public_dns)
    report_path = tmp_path / "example.json"
    report_path.write_text("{}", encoding="utf-8")

    def fake_engine(target, output_dir, progress_callback=None):
        report = {"risk": {"overall_score": 10, "overall_rating": "Low"}, "modules": {}}
        return {"report": report, "report_path": str(report_path)}

    monkeypatch.setattr("backend.app.services.job_service.SessionLocal", backend_client.app.state.test_session_factory)
    monkeypatch.setattr("backend.app.services.job_service.run_engine", fake_engine)

    response = backend_client.post(
        "/api/investigations/",
        headers={"X-API-Key": "test-key"},
        json={"target": "example.com"},
    )

    assert response.status_code == 202
    investigation_id = response.json()["id"]
    report = None
    for _ in range(20):
        report = backend_client.get(f"/api/investigations/{investigation_id}/report", headers={"X-API-Key": "test-key"})
        if report.status_code == 200:
            break
    assert report.status_code == 200
    assert report.json()["risk"]["overall_rating"] == "Low"


def test_frontend_is_served_by_fastapi(backend_client):
    response = backend_client.get("/app/")
    assert response.status_code == 200
    assert "PASSIVE RECONNAISSANCE SERVICE" in response.text
    assert "Scan target" in response.text
    assert "api-key" not in response.text


def test_public_scanner_accepts_target_without_api_key(backend_client, monkeypatch):
    monkeypatch.setattr("backend.app.services.target_security.socket.getaddrinfo", public_dns)
    monkeypatch.setattr("backend.app.api.web.submit_investigation", lambda investigation_id, target: None)

    response = backend_client.post("/web-api/investigations/", json={"target": "example.com"})

    assert response.status_code == 202
    assert response.json()["target"] == "example.com"


def test_report_path_traversal_is_rejected(backend_client, tmp_path):
    from backend.app.services.report_service import safe_report_path

    with pytest.raises(FileNotFoundError, match="outside"):
        safe_report_path(str(tmp_path.parent / "outside.json"))