"""
API endpoint integration tests for Guard AI FastAPI backend.
"""
from starlette.testclient import TestClient
from app.database import init_db
from app.main import app
from app.security.auth import issue_access_token
from app.config import settings
import json

init_db()
_test_users = json.loads(settings.AUTH_USERS_JSON)
TEST_ADMIN_USERNAME = _test_users[0]["username"]
TEST_ANALYST_USERNAME = _test_users[1]["username"]
client = TestClient(app, headers={"Authorization": f"Bearer {issue_access_token(TEST_ADMIN_USERNAME)}"})


def test_default_application_database_is_not_touched_by_test_imports_or_calls(default_database_unchanged):
    assert default_database_unchanged()


def test_auth_missing_invalid_and_expired_credentials(test_auth_users):
    unauthenticated = TestClient(app)
    assert unauthenticated.get("/api/v1/vault/status").status_code == 401

    bad_login = unauthenticated.post("/api/auth/token", json={"username": test_auth_users["admin_username"], "password": "wrong"})
    assert bad_login.status_code == 401
    good_login = unauthenticated.post("/api/auth/token", json={"username": test_auth_users["admin_username"], "password": test_auth_users["admin_password"]})
    assert good_login.status_code == 200
    assert good_login.json()["token_type"] == "bearer"

    signed = issue_access_token(test_auth_users["admin_username"])
    header, payload, signature = signed.split(".")
    altered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    invalid = unauthenticated.get("/api/v1/vault/status", headers={"Authorization": f"Bearer {header}.{payload}.{altered_signature}"})
    assert invalid.status_code == 401

    expired = issue_access_token(test_auth_users["admin_username"], now=1, expires_in=60)
    response = unauthenticated.get("/api/v1/vault/status", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_auth_enforces_role_permissions_and_persistent_revocation(test_auth_users):
    unauthenticated = TestClient(app)
    analyst_token = issue_access_token(test_auth_users["analyst_username"])
    denied = unauthenticated.get("/api/v1/vault/status", headers={"Authorization": f"Bearer {analyst_token}"})
    assert denied.status_code == 403
    allowed = unauthenticated.get("/api/v1/agents", headers={"Authorization": f"Bearer {analyst_token}"})
    assert allowed.status_code == 200

    admin_token = issue_access_token(test_auth_users["admin_username"])
    headers = {"Authorization": f"Bearer {admin_token}"}
    assert unauthenticated.post("/api/auth/revoke", headers=headers).status_code == 200
    assert unauthenticated.get("/api/v1/vault/status", headers=headers).status_code == 401


def test_authentication_configuration_missing_fails_closed(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "AUTH_USERS_JSON", "[]")
    unauthenticated = TestClient(app)
    assert unauthenticated.get("/api/v1/vault/status").status_code == 503
    assert unauthenticated.post("/api/auth/token", json={"username": "nobody", "password": "not-logged"}).status_code == 503


def test_database_unavailable_degrades_health_and_denies_protected_requests(monkeypatch):
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.orm import Session
    from app import main
    from app.database import get_db

    def unavailable_connect(*_args, **_kwargs):
        raise OperationalError("SELECT 1", {}, RuntimeError("database unavailable"))

    monkeypatch.setattr(main.engine, "connect", unavailable_connect)
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "DEGRADED"
    assert health.json()["database"] == "UNAVAILABLE"

    class BrokenSession:
        def query(self, *_args, **_kwargs):
            raise OperationalError("SELECT", {}, RuntimeError("database unavailable"))
        def rollback(self):
            pass

    def broken_db():
        yield BrokenSession()

    app.dependency_overrides[get_db] = broken_db
    try:
        protected = TestClient(app).get(
            "/api/v1/vault/status",
            headers={"Authorization": client.headers["Authorization"]},
        )
        assert protected.status_code == 503
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert data["system"] == "Guard AI"


def test_agents_listing_endpoint():
    response = client.get("/api/v1/agents")
    assert response.status_code == 200
    data = response.json()
    assert "agents" in data
    assert data["total"] >= 5


def test_agent_message_cannot_self_assert_high_impact_approval():
    response = client.post(
        "/api/v1/agents/message",
        json={
            "agent_id": "offence_ai",
            "message": {"action": "activate", "human_confirmed": True},
        },
    )
    assert response.status_code == 403
    assert "server-verified approval" in response.json()["detail"]


def test_emergency_action_requires_server_approved_bound_ticket():
    denied = client.post("/api/v1/emergency/activate", json={
        "level": "HEIGHTENED", "reason": "api test", "human_confirmed": True,
    })
    assert denied.status_code == 403
    requested = client.post("/api/v1/emergency/approvals", json={
        "action": "EMERGENCY_ACTIVATE", "target": None,
        "payload": {"level": "HEIGHTENED", "reason": "api test", "target": None},
    })
    assert requested.status_code == 200
    approval_id = requested.json()["approval_id"]
    assert client.post("/api/v1/emergency/approvals/approve", json={"approval_id": approval_id}).status_code == 200
    executed = client.post("/api/v1/emergency/activate", json={
        "level": "HEIGHTENED", "reason": "api test", "approval_id": approval_id,
    })
    assert executed.status_code == 200
    replay = client.post("/api/v1/emergency/activate", json={
        "level": "HEIGHTENED", "reason": "api test", "approval_id": approval_id,
    })
    assert replay.status_code == 403


def test_url_scan_endpoint():
    response = client.post("/api/v1/scan/url", json={"url": "http://microsoft-verify-account.xyz"})
    assert response.status_code == 200
    data = response.json()
    assert "report" in data
    assert "hybrid_explanation" in data
    assert data["report"]["composite_score"] > 0
    assert data["inspection"]["verdict"] in {"Unknown", "Suspicious", "Malicious"}


def test_pipeline_event_safe_link():
    response = client.post("/api/pipeline/event", json={"type": "link", "value": "https://example.com", "source": "pytest"})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Safe" and data["action"] == "allow"
    assert [step["name"] for step in data["steps"]] == ["Finder", "Controller", "Defence", "Informer", "Audit"]
    assert all(step["status"] in {"automatic", "waiting_for_approval"} for step in data["steps"])
    assert data["steps"][3]["result"]["english"] and data["steps"][3]["result"]["telugu"]


def test_pipeline_event_careful_link():
    response = client.post("/api/pipeline/event", json={"type": "link", "value": "https://a.b.example.com/verify", "source": "pytest"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "Careful"
    assert response.json()["action"] == "warn"


def test_pipeline_event_danger_link():
    response = client.post("/api/pipeline/event", json={"type": "link", "value": "http://microsoft-verify-account.xyz", "source": "pytest"})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Danger" and data["action"] == "block"
    assert data["steps"][2]["result"].startswith("Blocked automatically")
    assert "SIMULATED" in data["steps"][2]["result"]
    assert "waiting for approval" in data["steps"][2]["result"]


def test_inspection_report_is_persisted_with_privacy_minimized_url_metadata():
    secret_url = "https://example.test/path?access_token=do-not-store-this"
    scanned = client.post("/api/v1/scan/url", json={"url": secret_url})
    assert scanned.status_code == 200
    report_id = scanned.json()["inspection"]["report_id"]
    detail = client.get(f"/api/v1/scan/inspections/{report_id}")
    assert detail.status_code == 200
    serialized = json.dumps(detail.json())
    assert "do-not-store-this" not in serialized
    assert secret_url not in serialized
    assert detail.json()["report"]["verdict"] == "Unknown"


def test_file_inspection_persists_hash_without_file_content():
    response = client.post(
        "/api/v1/scan/file",
        files={"file": ("sample.txt", b"harmless static sample")},
    )
    assert response.status_code == 200
    inspection = response.json()["inspection"]
    assert len(inspection["sha256"]) == 64
    detail = client.get(f"/api/v1/scan/inspections/{inspection['report_id']}")
    assert detail.status_code == 200
    assert "harmless static sample" not in json.dumps(detail.json())


def test_text_scan_endpoint():
    response = client.post("/api/v1/scan/text", json={"text": "URGENT: Send bitcoin immediately to avoid arrest!"})
    assert response.status_code == 200
    data = response.json()
    assert data["report"]["composite_score"] >= 40


def test_vault_lifecycle_endpoint():
    # 1. Check status
    res_status = client.get("/api/v1/vault/status")
    assert res_status.status_code == 200

    # 2. Store item
    res_store = client.post(
        "/api/v1/vault/items",
        json={
            "label": "DB_PASSWORD",
            "plaintext": "SuperSecretPass9921!",
            "passphrase": "MasterKeyAlpha2026!",
            "category": "CREDENTIAL"
        }
    )
    assert res_store.status_code == 200
    item_id = res_store.json()["id"]

    # 3. Decrypt item with correct passphrase
    decrypt_payload = {"item_id": item_id, "passphrase": "MasterKeyAlpha2026!"}
    decrypt_approval = client.post("/api/v1/emergency/approvals", json={
        "action": "VAULT_ITEM_DECRYPT", "target": str(item_id), "payload": decrypt_payload,
    }).json()["approval_id"]
    assert client.post("/api/v1/emergency/approvals/approve", json={"approval_id": decrypt_approval}).status_code == 200
    res_dec = client.post(
        f"/api/v1/vault/items/{item_id}/decrypt",
        json={"passphrase": "MasterKeyAlpha2026!", "approval_id": decrypt_approval}
    )
    assert res_dec.status_code == 200
    assert res_dec.json()["plaintext"] == "SuperSecretPass9921!"

    # 4. Decrypt item with wrong passphrase fails
    wrong_payload = {"item_id": item_id, "passphrase": "WrongPassword!"}
    wrong_approval = client.post("/api/v1/emergency/approvals", json={
        "action": "VAULT_ITEM_DECRYPT", "target": str(item_id), "payload": wrong_payload,
    }).json()["approval_id"]
    assert client.post("/api/v1/emergency/approvals/approve", json={"approval_id": wrong_approval}).status_code == 200
    res_fail = client.post(
        f"/api/v1/vault/items/{item_id}/decrypt",
        json={"passphrase": "WrongPassword!", "approval_id": wrong_approval}
    )
    assert res_fail.status_code == 401


def test_audit_ledger_verification_endpoint():
    res = client.get("/api/v1/audit/verify")
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True


def test_blockchain_unavailable_reports_local_fallback():
    response = client.get("/api/v1/audit/blockchain/status")
    assert response.status_code == 200
    data = response.json()
    assert data["available"] is False
    assert data["mode"] == "LOCAL_HASH_CHAIN"


def test_recovery_envelope_round_trip_through_api():
    payload = "test recovery payload"
    generate_approval = client.post("/api/v1/emergency/approvals", json={
        "action": "VAULT_ESCROW_GENERATE", "target": "vault", "payload": {"payload": payload},
    }).json()["approval_id"]
    assert client.post("/api/v1/emergency/approvals/approve", json={"approval_id": generate_approval}).status_code == 200
    generated = client.post("/api/v1/vault/escrow", json={"payload": payload, "approval_id": generate_approval})
    assert generated.status_code == 200
    envelope = generated.json()
    approval_payload = {"recovery_key": envelope["recovery_key"], "encrypted_token": envelope["encrypted_token"]}
    approval = client.post("/api/v1/emergency/approvals", json={
        "action": "VAULT_ESCROW_RESTORE", "target": "vault", "payload": approval_payload,
    }).json()["approval_id"]
    assert client.post("/api/v1/emergency/approvals/approve", json={"approval_id": approval}).status_code == 200
    restored = client.post("/api/v1/vault/escrow/restore", json={**envelope, "approval_id": approval})
    assert restored.status_code == 200
    assert restored.json() == {"restored": True, "payload": "test recovery payload"}
    wrong = dict(envelope)
    wrong["recovery_key"] = "invalid recovery secret"
    wrong_payload = {"recovery_key": wrong["recovery_key"], "encrypted_token": wrong["encrypted_token"]}
    wrong_approval = client.post("/api/v1/emergency/approvals", json={
        "action": "VAULT_ESCROW_RESTORE", "target": "vault", "payload": wrong_payload,
    }).json()["approval_id"]
    assert client.post("/api/v1/emergency/approvals/approve", json={"approval_id": wrong_approval}).status_code == 200
    assert client.post("/api/v1/vault/escrow/restore", json={**wrong, "approval_id": wrong_approval}).status_code == 400


def test_emergency_status_endpoint():
    res = client.get("/api/v1/emergency/status")
    assert res.status_code == 200
    assert "lockdown_level" in res.json()


def test_android_companion_status_endpoint():
    res = client.get("/api/v1/android/status")
    assert res.status_code == 200
    assert res.json()["connection_status"] == "DEMONSTRATION"
    assert res.json()["demo_mode"] is True
    assert res.json()["paired"] is False


def test_emergency_requires_operator_confirmation():
    response = client.post("/api/v1/emergency/activate", json={"level": "HEIGHTENED"})
    assert response.status_code == 403
    response = client.post("/api/v1/emergency/reset", json={"human_confirmed": False})
    assert response.status_code == 403


def test_android_remote_lock_is_only_a_demo_action():
    response = client.post(
        "/api/v1/android/remote-lock",
        json={"device_id": "DEMO-ANDROID-01"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "SIMULATED_ONLY"
    assert response.json()["demo_mode"] is True


def test_sandbox_does_not_fetch_or_render_remote_pages():
    response = client.post("/api/v1/sandbox/preview-url", json={"url": "example.com"})
    assert response.status_code == 200
    assert response.json()["preview_available"] is False
    assert "sanitized_html" not in response.json()
