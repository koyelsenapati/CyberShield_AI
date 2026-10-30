"""
Access-control / IDOR / BOLA tests.

Every test uses the real HTTP API with real registered users. Admins are made
by changing the role column directly, because no API may grant a role.
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.jwt import create_access_token
from app.database.database import SessionLocal
from app.main import app
from app.models.report import Report
from tests._helpers import promote_to_admin, register_and_login

client = TestClient(app)

MISSING_ID = 2_000_000_000

# ===================================================================== users

def test_users_endpoints_require_authentication():
    assert client.get("/users/").status_code == 401
    assert client.get("/users/1").status_code == 401
    assert client.delete("/users/1").status_code == 401

def test_regular_user_cannot_list_users():
    user = register_and_login(client)
    assert client.get("/users/", headers=user["headers"]).status_code == 403

def test_admin_can_list_users_and_no_password_hash_is_exposed():
    admin = register_and_login(client, prefix="admin")
    other = register_and_login(client)
    promote_to_admin(admin["id"])

    response = client.get("/users/", headers=admin["headers"])
    assert response.status_code == 200
    ids = {u["id"] for u in response.json()}
    assert {admin["id"], other["id"]} <= ids
    assert all("hashed_password" not in u for u in response.json())

def test_user_can_view_self_but_not_others():
    me = register_and_login(client)
    other = register_and_login(client)

    assert client.get(f"/users/{me['id']}", headers=me["headers"]).status_code == 200

    other_resp = client.get(f"/users/{other['id']}", headers=me["headers"])
    missing_resp = client.get(f"/users/{MISSING_ID}", headers=me["headers"])
    assert other_resp.status_code == 404
    # Same answer as a non-existent ID: IDs cannot be enumerated.
    assert other_resp.json() == missing_resp.json()

def test_admin_can_view_any_user():
    admin = register_and_login(client, prefix="admin")
    other = register_and_login(client)
    promote_to_admin(admin["id"])

    response = client.get(f"/users/{other['id']}", headers=admin["headers"])
    assert response.status_code == 200
    assert response.json()["id"] == other["id"]

def test_regular_user_cannot_delete_anyone():
    attacker = register_and_login(client)
    victim = register_and_login(client)
    admin = register_and_login(client, prefix="admin")
    promote_to_admin(admin["id"])

    assert client.delete(f"/users/{victim['id']}", headers=attacker["headers"]).status_code == 403
    assert client.delete(f"/users/{attacker['id']}", headers=attacker["headers"]).status_code == 403
    # Victim still exists.
    assert client.get(f"/users/{victim['id']}", headers=admin["headers"]).status_code == 200

def test_admin_can_delete_other_user_but_not_self():
    admin = register_and_login(client, prefix="admin")
    victim = register_and_login(client)
    promote_to_admin(admin["id"])

    assert client.delete(f"/users/{admin['id']}", headers=admin["headers"]).status_code == 400
    assert client.delete(f"/users/{victim['id']}", headers=admin["headers"]).status_code == 200
    assert client.get(f"/users/{victim['id']}", headers=admin["headers"]).status_code == 404

def test_role_claim_inside_a_token_is_not_trusted():
    user = register_and_login(client)
    forged = create_access_token({"sub": str(user["id"]), "role": "admin"})
    headers = {"Authorization": f"Bearer {forged}"}
    assert client.get("/users/", headers=headers).status_code == 403

# ==================================================================== alerts

def test_alerts_require_authentication():
    assert client.get("/alerts/").status_code == 401
    assert client.post("/alerts/", json={"title": "t", "description": "d", "severity": "Low"}).status_code == 401

def test_alert_owner_cannot_be_chosen_from_the_request_body():
    attacker = register_and_login(client)
    victim = register_and_login(client)

    created = client.post(
        "/alerts/",
        json={"title": "Planted", "description": "x", "severity": "Low", "user_id": victim["id"]},
        headers=attacker["headers"],
    )
    assert created.status_code == 200
    alert_id = created.json()["id"]

    victim_ids = {a["id"] for a in client.get("/alerts/", headers=victim["headers"]).json()}
    attacker_ids = {a["id"] for a in client.get("/alerts/", headers=attacker["headers"]).json()}
    assert alert_id not in victim_ids
    assert alert_id in attacker_ids

# =================================================================== reports

def _make_report(owner_id: int, tmp_path, with_json: bool = True) -> int:
    pdf = tmp_path / f"{uuid.uuid4().hex}.pdf"
    pdf.write_bytes(b"%PDF-1.4\n")
    json_path = None
    if with_json:
        json_path = tmp_path / f"{uuid.uuid4().hex}.json"
        json_path.write_text(json.dumps({"ok": True}), encoding="utf-8")

    db = SessionLocal()
    try:
        report = Report(
            user_id=owner_id,
            report_type="PDF",
            file_path=str(pdf),
            json_file_path=str(json_path) if json_path else None,
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report.id
    finally:
        db.close()

def test_reports_require_authentication():
    assert client.get("/reports/pdf/1").status_code == 401
    assert client.get("/reports/json/1").status_code == 401

def test_report_pdf_and_json_are_owner_only(tmp_path):
    owner = register_and_login(client)
    other = register_and_login(client)
    report_id = _make_report(owner["id"], tmp_path)

    for kind in ("pdf", "json"):
        assert client.get(f"/reports/{kind}/{report_id}", headers=owner["headers"]).status_code == 200
        denied = client.get(f"/reports/{kind}/{report_id}", headers=other["headers"])
        missing = client.get(f"/reports/{kind}/{MISSING_ID}", headers=other["headers"])
        assert denied.status_code == 404
        assert denied.json() == missing.json()  # indistinguishable from "does not exist"

# ================================================================== incidents

def _incident(user, **overrides):
    body = {"title": "Suspicious login", "severity": "High", "description": "from test"}
    body.update(overrides)
    response = client.post("/incidents/", json=body, headers=user["headers"])
    assert response.status_code == 201, response.text
    return response.json()

def test_incidents_require_authentication():
    assert client.get("/incidents/").status_code == 401
    assert client.get("/incidents/1").status_code == 401
    assert client.post("/incidents/", json={"title": "x"}).status_code == 401
    assert client.patch("/incidents/1", json={"status": "Closed"}).status_code == 401

def test_incident_owner_comes_from_the_token_not_the_body():
    attacker = register_and_login(client)
    victim = register_and_login(client)
    created = _incident(attacker, user_id=victim["id"])
    assert created["user_id"] == attacker["id"]

def test_incident_listing_is_scoped_to_the_caller():
    a = register_and_login(client)
    b = register_and_login(client)
    mine = _incident(a)
    theirs = _incident(b)

    a_ids = {i["id"] for i in client.get("/incidents/", headers=a["headers"]).json()}
    assert mine["id"] in a_ids and theirs["id"] not in a_ids

def test_incident_get_and_patch_by_non_owner_is_404_and_changes_nothing():
    owner = register_and_login(client)
    attacker = register_and_login(client)
    incident = _incident(owner)

    assert client.get(f"/incidents/{incident['id']}", headers=attacker["headers"]).status_code == 404
    patched = client.patch(
        f"/incidents/{incident['id']}",
        json={"status": "Closed", "resolution": "pwned", "user_id": attacker["id"]},
        headers=attacker["headers"],
    )
    assert patched.status_code == 404

    unchanged = client.get(f"/incidents/{incident['id']}", headers=owner["headers"]).json()
    assert unchanged["status"] == "Open"
    assert unchanged["resolution"] is None
    assert unchanged["user_id"] == owner["id"]

def test_incident_owner_can_update_but_not_reassign_ownership():
    owner = register_and_login(client)
    other = register_and_login(client)
    incident = _incident(owner)

    response = client.patch(
        f"/incidents/{incident['id']}",
        json={"status": "Investigating", "analyst_notes": "looking", "user_id": other["id"]},
        headers=owner["headers"],
    )
    assert response.status_code == 200
    assert response.json()["status"] == "Investigating"
    assert response.json()["user_id"] == owner["id"]

def test_incident_missing_id_is_404():
    user = register_and_login(client)
    assert client.get(f"/incidents/{MISSING_ID}", headers=user["headers"]).status_code == 404

@pytest.mark.parametrize(
    "body",
    [
        {"title": ""},
        {"title": "x", "severity": "Catastrophic"},
        {"title": "x" * 256},
    ],
)
def test_incident_create_validation(body):
    user = register_and_login(client)
    assert client.post("/incidents/", json=body, headers=user["headers"]).status_code == 422

def test_incident_update_validation_and_no_delete_route():
    user = register_and_login(client)
    incident = _incident(user)
    assert client.patch(f"/incidents/{incident['id']}", json={"status": "Nope"}, headers=user["headers"]).status_code == 422
    assert client.delete(f"/incidents/{incident['id']}", headers=user["headers"]).status_code == 405

# ========================================================== network statistics

def test_network_statistics_requires_authentication():
    assert client.get("/network/statistics").status_code == 401

def test_network_statistics_with_token():
    user = register_and_login(client)
    response = client.get("/network/statistics", headers=user["headers"])
    assert response.status_code == 200
    assert "statistics" in response.json()

# ============================================================== file integrity

@pytest.fixture()
def fim_base(tmp_path, monkeypatch):
    base = tmp_path / "fim_root"
    base.mkdir()
    monkeypatch.setattr(settings, "FILE_INTEGRITY_BASE_DIR", str(base))
    return base

def _put(base, user_id, rel, content=b"hello"):
    path = base / str(user_id) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path

def _scan(user, file_path):
    return client.post("/file-integrity/", params={"file_path": file_path}, headers=user["headers"])

def test_file_integrity_requires_authentication(fim_base):
    assert client.post("/file-integrity/", params={"file_path": "a.txt"}).status_code == 401

def test_file_integrity_baseline_unchanged_modified_flow(fim_base):
    user = register_and_login(client)
    target = _put(fim_base, user["id"], "app/config.ini", b"v1")

    first = _scan(user, "app/config.ini")
    assert first.status_code == 200, first.text
    scan = first.json()["scan"]
    assert scan["status"] == "Baseline"
    assert scan["user_id"] == user["id"]
    assert scan["file_path"] == "app/config.ini"       # relative, no server layout
    assert str(fim_base) not in first.text

    assert _scan(user, "app/config.ini").json()["scan"]["status"] == "Unchanged"

    target.write_bytes(b"v2-tampered")
    modified = _scan(user, "app/config.ini").json()["scan"]
    assert modified["status"] == "Modified"
    assert modified["file_hash"] != scan["file_hash"]

def test_file_integrity_baselines_are_per_user(fim_base):
    a = register_and_login(client)
    b = register_and_login(client)
    _put(fim_base, a["id"], "same.txt", b"A")
    _put(fim_base, b["id"], "same.txt", b"B")
    assert _scan(a, "same.txt").json()["scan"]["status"] == "Baseline"
    assert _scan(b, "same.txt").json()["scan"]["status"] == "Baseline"

def test_file_integrity_cannot_reach_another_users_directory(fim_base):
    a = register_and_login(client)
    b = register_and_login(client)
    _put(fim_base, b["id"], "secret.txt", b"top secret")

    traversal = _scan(a, f"../{b['id']}/secret.txt")
    assert traversal.status_code == 400
    assert "top secret" not in traversal.text
    # A's own directory has no such file.
    assert _scan(a, "secret.txt").status_code == 404

@pytest.mark.parametrize("path", ["../outside.txt", "a/../../outside.txt", "..", "../.."])
def test_file_integrity_rejects_traversal(fim_base, path):
    user = register_and_login(client)
    (fim_base / "outside.txt").write_text("x")
    assert _scan(user, path).status_code == 400

def test_file_integrity_rejects_absolute_paths(fim_base, tmp_path):
    user = register_and_login(client)
    outside = tmp_path / "abs.txt"
    outside.write_text("x")
    assert _scan(user, str(outside)).status_code == 400
    assert _scan(user, "/etc/passwd").status_code == 400

def test_file_integrity_rejects_symlink_escape(fim_base, tmp_path):
    user = register_and_login(client)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("secret")
    user_dir = fim_base / str(user["id"])
    user_dir.mkdir()
    try:
        (user_dir / "link.txt").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported here")
    assert _scan(user, "link.txt").status_code == 400

def test_file_integrity_errors_do_not_leak_server_paths(fim_base):
    user = register_and_login(client)
    missing = _scan(user, "nope.txt")
    assert missing.status_code == 404
    assert str(fim_base) not in missing.text

    (fim_base / str(user["id"]) / "adir").mkdir(parents=True)
    assert _scan(user, "adir").status_code == 404

def test_file_integrity_nul_and_empty_inputs(fim_base):
    user = register_and_login(client)
    assert _scan(user, "a\x00b").status_code == 400
    assert _scan(user, "").status_code == 422
    assert client.post("/file-integrity/", headers=user["headers"]).status_code == 422
