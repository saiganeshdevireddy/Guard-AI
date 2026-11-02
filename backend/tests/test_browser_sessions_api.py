"""FastAPI contract tests. Worker evidence below is a test double only; no worker exists."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient

from sqlalchemy.exc import SQLAlchemyError

from app.core.audit_chain import AuditChainService
from app.database import (
    AuditEntry,
    BrowserSessionRecord,
    SessionLocal,
    WorkerAuthorizationTicketRecord,
    init_db,
)
from app.agents.controller import controller_ai
from app.main import app
from app.routers.browser_sessions_api import (
    get_defence_policy_enabled,
    get_worker_id,
    get_worker_registry,
)
from app.security.auth import issue_access_token
from app.services.browser_session_manager import WorkerHealth, WorkerRegistration, WorkerRegistry


init_db()


@pytest.fixture(autouse=True)
def clear_dependency_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _client(username: str):
    token = issue_access_token(username)
    return TestClient(app, headers={"Authorization": f"Bearer {token}"})


def _allow_test_policy(monkeypatch, *, registration="default"):
    """Test-only evidence source; never installed as an application dependency."""
    evidence = registration
    if registration == "default":
        evidence = WorkerRegistration(
            "test-worker",
            WorkerHealth.HEALTHY,
            datetime.now(timezone.utc),
            evidence_verified=True,
        )
    registry = Mock(spec=WorkerRegistry)
    registry.get_registration.return_value = evidence
    monkeypatch.setitem(app.dependency_overrides, get_defence_policy_enabled, lambda: True)
    monkeypatch.setattr(controller_ai.defence, "_browser_session_policy_enabled", True)
    monkeypatch.setitem(app.dependency_overrides, get_worker_id, lambda: "test-worker")
    monkeypatch.setitem(app.dependency_overrides, get_worker_registry, lambda: registry)
    return registry


def _seed_session(owner_id: str, state: str, worker_id: str | None = None) -> str:
    session_id = secrets.token_urlsafe(24)
    db = SessionLocal()
    try:
        db.add(BrowserSessionRecord(
            session_id=session_id,
            owner_id=owner_id,
            idempotency_key_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
            state=state,
            worker_id=worker_id,
            policy_version="browser-session-policy-v1",
        ))
        db.commit()
    finally:
        db.close()
    return session_id


def _create(client, *, key=None, explicit=True):
    key = key or secrets.token_urlsafe(24)
    return client.post(
        "/api/v1/sandbox/sessions",
        headers={"Idempotency-Key": key},
        json={"explicit_user_authorization": explicit},
    )


def test_create_requires_authentication():
    response = TestClient(app).post(
        "/api/v1/sandbox/sessions",
        headers={"Idempotency-Key": "api-idempotency-key-0001"},
        json={"explicit_user_authorization": True},
    )
    assert response.status_code == 401


def test_create_rejects_roles_without_sandbox_permission(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    response = _create(_client(test_auth_users["analyst_username"]))
    assert response.status_code == 403
    assert "permission" in response.json()["detail"].lower()


def test_client_cannot_supply_owner_worker_or_defence_approval(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    response = _client(test_auth_users["admin_username"]).post(
        "/api/v1/sandbox/sessions",
        headers={"Idempotency-Key": "api-idempotency-key-0001"},
        json={
            "explicit_user_authorization": True,
            "owner_id": "another-user",
            "worker_id": "untrusted-worker",
            "defence_approved": True,
        },
    )
    assert response.status_code == 422


def test_session_ownership_is_derived_from_authenticated_principal(test_auth_users):
    session_id = _seed_session("someone-else", "AUTHORIZED")
    response = _client(test_auth_users["admin_username"]).get(f"/api/v1/sandbox/sessions/{session_id}")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "session_not_found"


def test_session_cancellation_requires_authentication():
    response = TestClient(app).delete("/api/v1/sandbox/sessions/abcdefghijklmnopqrstuvwxyz")
    assert response.status_code == 401


def test_only_session_owner_can_cancel_authorization(test_auth_users):
    session_id = _seed_session("someone-else", "AUTHORIZED", "test-worker")
    response = _client(test_auth_users["admin_username"]).delete(
        f"/api/v1/sandbox/sessions/{session_id}"
    )
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "session_not_found"


def _seed_ticket(session_id: str, owner_id: str, worker_id: str = "test-worker") -> str:
    ticket_id = secrets.token_urlsafe(24)
    db = SessionLocal()
    try:
        db.add(WorkerAuthorizationTicketRecord(
            ticket_id=ticket_id,
            jti_hash=hashlib.sha256(ticket_id.encode("ascii")).hexdigest(),
            delivery_id_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
            key_id="test-key",
            session_id=session_id,
            worker_id=worker_id,
            subject_id=owner_id,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
        ))
        db.commit()
    finally:
        db.close()
    return ticket_id


def test_cancelling_authorized_session_revokes_worker_tickets_and_is_idempotent(test_auth_users):
    owner = test_auth_users["admin_username"]
    session_id = _seed_session(owner, "AUTHORIZED", "test-worker")
    ticket_id = _seed_ticket(session_id, owner)
    client = _client(owner)

    first = client.delete(f"/api/v1/sandbox/sessions/{session_id}")
    second = client.delete(f"/api/v1/sandbox/sessions/{session_id}")

    assert first.status_code == second.status_code == 200
    assert first.json()["state"] == second.json()["state"] == "CANCELLED"
    assert first.json()["runtime_started"] is False
    db = SessionLocal()
    try:
        session = db.query(BrowserSessionRecord).filter_by(session_id=session_id).one()
        ticket = db.query(WorkerAuthorizationTicketRecord).filter_by(ticket_id=ticket_id).one()
        event = db.query(AuditEntry).filter_by(
            event_type="BROWSER_SESSION_AUTHORIZATION_CANCELLED",
            actor=owner,
        ).one()
        assert session.state == "CANCELLED"
        assert ticket.revoked_at is not None
        assert event is not None
    finally:
        db.close()

    cannot_provision = client.post(f"/api/v1/sandbox/sessions/{session_id}/provision")
    assert cannot_provision.status_code == 409


def test_cancellation_rejects_non_authorized_lifecycle_states(test_auth_users):
    session_id = _seed_session(test_auth_users["admin_username"], "PROVISIONING", "test-worker")
    response = _client(test_auth_users["admin_username"]).delete(
        f"/api/v1/sandbox/sessions/{session_id}"
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "invalid_session_transition"


def test_audit_failure_rolls_back_session_cancellation_and_ticket_revocation(
    test_auth_users, monkeypatch
):
    owner = test_auth_users["admin_username"]
    session_id = _seed_session(owner, "AUTHORIZED", "test-worker")
    ticket_id = _seed_ticket(session_id, owner)

    def fail_audit(*args, **kwargs):
        raise SQLAlchemyError("simulated audit database failure")

    monkeypatch.setattr(AuditChainService, "record_event", staticmethod(fail_audit))
    response = _client(owner).delete(f"/api/v1/sandbox/sessions/{session_id}")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "session_store_unavailable"

    db = SessionLocal()
    try:
        session = db.query(BrowserSessionRecord).filter_by(session_id=session_id).one()
        ticket = db.query(WorkerAuthorizationTicketRecord).filter_by(ticket_id=ticket_id).one()
        assert session.state == "AUTHORIZED"
        assert ticket.revoked_at is None
    finally:
        db.close()


def test_defence_policy_defaults_to_deny(test_auth_users):
    response = _create(_client(test_auth_users["admin_username"]))
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "browser_session_unavailable"


def test_invalid_defence_policy_configuration_fails_closed(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    monkeypatch.setitem(app.dependency_overrides, get_defence_policy_enabled, lambda: None)
    response = _create(_client(test_auth_users["admin_username"]))
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "browser_session_policy_unavailable"


def test_explicit_authorization_denial_creates_no_record(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    response = _create(_client(test_auth_users["admin_username"]), explicit=False)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "explicit_authorization_required"


@pytest.mark.parametrize(
    "registration",
    [
        None,
        WorkerRegistration("test-worker"),
        WorkerRegistration("test-worker", WorkerHealth.UNHEALTHY, datetime.now(timezone.utc), True),
        WorkerRegistration("test-worker", WorkerHealth.HEALTHY, datetime.now(timezone.utc) - timedelta(minutes=5), True),
        WorkerRegistration("test-worker", WorkerHealth.HEALTHY, datetime.now(timezone.utc), False),
    ],
)
def test_missing_unhealthy_stale_or_unverified_worker_evidence_is_denied(
    test_auth_users, monkeypatch, registration
):
    _allow_test_policy(monkeypatch, registration=registration)
    response = _create(_client(test_auth_users["admin_username"]))
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "browser_session_unavailable"


def test_permitted_policy_operation_records_authorization_only(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    client = _client(test_auth_users["admin_username"])
    response = _create(client)
    assert response.status_code == 201
    body = response.json()
    assert body["state"] == "AUTHORIZED"
    assert body["runtime_started"] is False
    assert body["runtime_status"] == "NOT_IMPLEMENTED"
    assert "worker_id" not in body
    assert "owner_id" not in body

    stored = client.get(f"/api/v1/sandbox/sessions/{body['session_id']}")
    assert stored.status_code == 200
    assert stored.json()["state"] == "AUTHORIZED"
    assert stored.json()["runtime_started"] is False


def test_duplicate_idempotency_key_returns_same_authorization(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    client = _client(test_auth_users["admin_username"])
    key = "duplicate-request-key-0001"
    first = _create(client, key=key)
    second = _create(client, key=key)
    assert first.status_code == second.status_code == 201
    assert first.json()["session_id"] == second.json()["session_id"]


def test_provisioning_is_rejected_without_supervisor_evidence(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    client = _client(test_auth_users["admin_username"])
    created = _create(client)
    session_id = created.json()["session_id"]
    response = client.post(f"/api/v1/sandbox/sessions/{session_id}/provision")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "browser_runtime_unavailable"
    status_response = client.get(f"/api/v1/sandbox/sessions/{session_id}")
    assert status_response.json()["state"] == "AUTHORIZED"
    assert status_response.json()["runtime_started"] is False


def test_invalid_lifecycle_transition_is_rejected(test_auth_users):
    session_id = _seed_session(test_auth_users["admin_username"], "DENIED")
    response = _client(test_auth_users["admin_username"]).post(
        f"/api/v1/sandbox/sessions/{session_id}/provision"
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "invalid_session_transition"


def test_cleanup_without_verifier_is_rejected_and_state_is_retained(test_auth_users):
    session_id = _seed_session(test_auth_users["admin_username"], "CLEANUP_PENDING", "worker-test")
    client = _client(test_auth_users["admin_username"])
    response = client.post(f"/api/v1/sandbox/sessions/{session_id}/close")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "cleanup_unverified"
    assert client.get(f"/api/v1/sandbox/sessions/{session_id}").json()["state"] == "CLEANUP_PENDING"
