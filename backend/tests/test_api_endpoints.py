"""
API endpoint integration tests for Guard AI FastAPI backend.
"""
from starlette.testclient import TestClient
from app.database import init_db
from app.main import app

init_db()
client = TestClient(app)


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


def test_emergency_status_endpoint():
    res = client.get("/api/v1/emergency/status")
    assert res.status_code == 200
    assert "lockdown_level" in res.json()


def test_android_companion_status_endpoint():
    res = client.get("/api/v1/android/status")
    assert res.status_code == 200
    assert res.json()["connection_status"] == "ONLINE"
