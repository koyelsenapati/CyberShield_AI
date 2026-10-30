import uuid

from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.core.jwt import verify_access_token
from app.database.database import SessionLocal
from app.main import app
from app.models.report import Report

client = TestClient(app)

def _new_user_headers():
    username = f"boundary_{uuid.uuid4().hex[:10]}"
    password = "Test@12345"
    response = client.post(
        "/auth/register",
        json={
            "username": username,
            "full_name": "Boundary Test User",
            "email": f"{username}@example.com",
            "password": password,
        },
    )
    assert response.status_code in {200, 201}
    login = client.post(
        "/auth/login",
        json={"email": f"{username}@example.com", "password": password},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}

def _user_id(headers):
    token = headers["Authorization"].removeprefix("Bearer ")
    payload = verify_access_token(token)
    assert payload and payload.get("sub")
    return int(payload["sub"])

def test_alerts_are_scoped_to_the_authenticated_user():
    first_headers = _new_user_headers()
    second_headers = _new_user_headers()
    created = client.post(
        "/alerts/",
        json={"title": "User-specific alert", "description": "Scoped", "severity": "Low"},
        headers=first_headers,
    )
    assert created.status_code == 200

    first_alerts = client.get("/alerts/", headers=first_headers)
    second_alerts = client.get("/alerts/", headers=second_headers)
    assert first_alerts.status_code == 200
    assert second_alerts.status_code == 200
    assert created.json()["id"] in {alert["id"] for alert in first_alerts.json()}
    assert created.json()["id"] not in {alert["id"] for alert in second_alerts.json()}

def test_file_integrity_scan_is_owned_by_the_requesting_user(tmp_path, monkeypatch):
    # The endpoint now only reads <FILE_INTEGRITY_BASE_DIR>/<user id>/..., so the
    # old absolute-path form of this test (which hashed an arbitrary server
    # path) is no longer valid and is replaced, not deleted.
    base = tmp_path / "fim_root"
    monkeypatch.setattr(settings, "FILE_INTEGRITY_BASE_DIR", str(base))
    headers = _new_user_headers()
    user_id = _user_id(headers)
    target = base / str(user_id) / "integrity-target.txt"
    target.parent.mkdir(parents=True)
    target.write_text("integrity test", encoding="utf-8")

    response = client.post(
        "/file-integrity/",
        params={"file_path": "integrity-target.txt"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["scan"]["user_id"] == user_id

def test_reports_require_ownership(tmp_path):
    owner_headers = _new_user_headers()
    other_headers = _new_user_headers()
    report_path = tmp_path / "owned-report.pdf"
    report_path.write_bytes(b"%PDF-1.4\n")

    db = SessionLocal()
    try:
        report = Report(
            user_id=_user_id(owner_headers),
            report_type="PDF",
            file_path=str(report_path),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        assert client.get(f"/reports/pdf/{report.id}", headers=owner_headers).status_code == 200
        assert client.get(f"/reports/pdf/{report.id}", headers=other_headers).status_code == 404
    finally:
        db.close()

def test_network_websocket_accepts_a_valid_token():
    headers = _new_user_headers()
    token = headers["Authorization"].removeprefix("Bearer ")

    with client.websocket_connect(f"/ws/network?token={token}") as socket:
        message = socket.receive_json()
        assert "statistics" in message
        assert "packets" in message
