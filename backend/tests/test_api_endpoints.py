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


def test_url_scan_endpoint():
    response = client.post("/api/v1/scan/url", json={"url": "http://microsoft-verify-account.xyz"})
    assert response.status_code == 200
    data = response.json()
    assert "report" in data
    assert "hybrid_explanation" in data
    assert data["report"]["composite_score"] > 0


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
    res_dec = client.post(
        f"/api/v1/vault/items/{item_id}/decrypt",
        json={"passphrase": "MasterKeyAlpha2026!"}
    )
    assert res_dec.status_code == 200
    assert res_dec.json()["plaintext"] == "SuperSecretPass9921!"

    # 4. Decrypt item with wrong passphrase fails
    res_fail = client.post(
        f"/api/v1/vault/items/{item_id}/decrypt",
        json={"passphrase": "WrongPassword!"}
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
    generated = client.post("/api/v1/vault/escrow", json={"payload": "test recovery payload"})
    assert generated.status_code == 200
    envelope = generated.json()
    restored = client.post("/api/v1/vault/escrow/restore", json=envelope)
    assert restored.status_code == 200
    assert restored.json() == {"restored": True, "payload": "test recovery payload"}
    wrong = dict(envelope)
    wrong["recovery_key"] = "invalid recovery secret"
    assert client.post("/api/v1/vault/escrow/restore", json=wrong).status_code == 400


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
