"""Persistence and transaction tests for browser-session authorization metadata."""
import hashlib
import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from app.database import (
    BrowserSessionRecord,
    SessionLocal,
    _ensure_browser_session_columns,
    _ensure_worker_ticket_delivery_column,
    _ensure_worker_ticket_key_id_column,
    _ensure_worker_health_evidence_columns,
    engine,
    get_db,
    init_db,
)
from app.main import app
from app.routers.browser_sessions_api import (
    get_defence_policy_enabled,
    get_worker_id,
    get_worker_registry,
)
from app.config import settings
from app.agents.controller import controller_ai
from app.security.auth import hash_password, issue_access_token
from app.services.browser_session_manager import WorkerHealth, WorkerRegistration, WorkerRegistry
from unittest.mock import Mock

init_db()


@pytest.fixture(autouse=True)
def clear_dependency_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _client(username: str):
    token = issue_access_token(username)
    return TestClient(app, headers={"Authorization": f"Bearer {token}"})


def _allow_test_policy(monkeypatch):
    registry = Mock(spec=WorkerRegistry)
    registry.get_registration.return_value = WorkerRegistration(
        "test-worker", WorkerHealth.HEALTHY, datetime.now(timezone.utc), evidence_verified=True
    )
    monkeypatch.setitem(app.dependency_overrides, get_defence_policy_enabled, lambda: True)
    monkeypatch.setattr(controller_ai.defence, "_browser_session_policy_enabled", True)
    monkeypatch.setitem(app.dependency_overrides, get_worker_id, lambda: "test-worker")
    monkeypatch.setitem(app.dependency_overrides, get_worker_registry, lambda: registry)


def _create(client, key=None):
    return client.post(
        "/api/v1/sandbox/sessions",
        headers={"Idempotency-Key": key or secrets.token_urlsafe(24)},
        json={"explicit_user_authorization": True},
    )


def test_authorization_persists_across_database_sessions_and_reinitialization(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    response = _create(_client(test_auth_users["admin_username"]))
    assert response.status_code == 201, response.text
    session_id = response.json()["session_id"]

    # Simulate application/database reinitialization, then use a fresh ORM session.
    engine.dispose()
    init_db()
    db = SessionLocal()
    try:
        record = db.query(BrowserSessionRecord).filter_by(session_id=session_id).one()
        assert record.state == "AUTHORIZED"
        assert record.owner_id == test_auth_users["admin_username"]
        assert record.created_at is not None
        assert record.authorized_at is not None
        assert record.updated_at is not None
    finally:
        db.close()

    reread = _client(test_auth_users["admin_username"]).get(
        f"/api/v1/sandbox/sessions/{session_id}"
    )
    assert reread.status_code == 200
    assert reread.json()["state"] == "AUTHORIZED"
    assert reread.json()["runtime_started"] is False


def test_owner_isolation_applies_to_persisted_records(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    configured = json.loads(settings.AUTH_USERS_JSON)
    configured.append({
        "username": "pytest-other-admin",
        "password_hash": hash_password(secrets.token_urlsafe(32)),
        "role": "admin",
        "active": True,
    })
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", json.dumps(configured))
    created = _create(_client(test_auth_users["admin_username"]))
    session_id = created.json()["session_id"]
    other_owner = _client("pytest-other-admin")
    response = other_owner.get(f"/api/v1/sandbox/sessions/{session_id}")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "session_not_found"


def test_duplicate_idempotency_is_stable_across_database_sessions(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    client = _client(test_auth_users["admin_username"])
    key = "persistent-idempotency-key-0001"
    first = _create(client, key)
    engine.dispose()
    init_db()
    second = _create(_client(test_auth_users["admin_username"]), key)
    assert first.status_code == second.status_code == 201
    assert first.json()["session_id"] == second.json()["session_id"]
    db = SessionLocal()
    try:
        assert db.query(BrowserSessionRecord).filter_by(
            owner_id=test_auth_users["admin_username"],
            idempotency_key_hash=hashlib.sha256(key.encode()).hexdigest(),
        ).count() == 1
    finally:
        db.close()


def test_concurrent_duplicate_requests_create_one_record(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)
    username = test_auth_users["admin_username"]
    key = "concurrent-idempotency-key-001"

    def send_request(_):
        return _create(_client(username), key)

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(send_request, range(2)))
    assert [response.status_code for response in responses] == [201, 201]
    assert responses[0].json()["session_id"] == responses[1].json()["session_id"]
    db = SessionLocal()
    try:
        assert db.query(BrowserSessionRecord).filter_by(
            owner_id=username,
            idempotency_key_hash=hashlib.sha256(key.encode()).hexdigest(),
        ).count() == 1
    finally:
        db.close()


def test_database_write_failure_rolls_back_and_returns_error(test_auth_users, monkeypatch):
    _allow_test_policy(monkeypatch)

    class FailingCommitSession(Session):
        def commit(self):
            self.flush()  # Issue the INSERT inside the transaction before simulating failure.
            raise SQLAlchemyError("simulated commit failure")

    def failing_db():
        db = FailingCommitSession(bind=engine, autoflush=False, autocommit=False)
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setitem(app.dependency_overrides, get_db, failing_db)
    response = _create(_client(test_auth_users["admin_username"]), "failed-write-key-0000001")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "session_store_unavailable"

    db = SessionLocal()
    try:
        assert db.query(BrowserSessionRecord).filter_by(
            owner_id=test_auth_users["admin_username"],
            idempotency_key_hash=hashlib.sha256(b"failed-write-key-0000001").hexdigest(),
        ).one_or_none() is None
    finally:
        db.close()


def test_interrupted_lifecycle_state_is_preserved_without_false_recovery(test_auth_users):
    session_id = secrets.token_urlsafe(24)
    timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
    db = SessionLocal()
    try:
        db.add(BrowserSessionRecord(
            session_id=session_id,
            owner_id=test_auth_users["admin_username"],
            idempotency_key_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
            state="PROVISIONING",
            policy_version="browser-session-policy-v1",
            created_at=timestamp,
            authorized_at=timestamp,
            updated_at=timestamp,
        ))
        db.commit()
    finally:
        db.close()

    engine.dispose()
    init_db()
    response = _client(test_auth_users["admin_username"]).get(
        f"/api/v1/sandbox/sessions/{session_id}"
    )
    assert response.status_code == 200
    assert response.json()["state"] == "PROVISIONING"
    assert response.json()["runtime_status"] == "NOT_IMPLEMENTED"


def test_additive_schema_update_preserves_existing_rows():
    old_engine = create_engine("sqlite:///:memory:")
    try:
        with old_engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE browser_sessions (session_id VARCHAR(64) PRIMARY KEY, "
                "owner_id VARCHAR(128) NOT NULL, idempotency_key_hash VARCHAR(64) NOT NULL, "
                "state VARCHAR(32) NOT NULL, created_at DATETIME NOT NULL)"
            ))
            connection.execute(text(
                "INSERT INTO browser_sessions VALUES "
                "('preserved-session', 'owner', 'hash', 'AUTHORIZED', '2026-01-01 00:00:00')"
            ))
        _ensure_browser_session_columns(old_engine)
        columns = {column["name"] for column in inspect(old_engine).get_columns("browser_sessions")}
        assert {"authorized_at", "updated_at"}.issubset(columns)
        with old_engine.connect() as connection:
            row = connection.execute(text(
                "SELECT state, created_at, authorized_at, updated_at "
                "FROM browser_sessions WHERE session_id = 'preserved-session'"
            )).one()
        assert row.state == "AUTHORIZED"
        assert row.created_at == row.authorized_at == row.updated_at
    finally:
        old_engine.dispose()


def test_worker_ticket_schema_upgrade_rejects_legacy_duplicate_sessions_without_deleting_data():
    old_engine = create_engine("sqlite:///:memory:")
    try:
        with old_engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE worker_authorization_tickets ("
                "ticket_id VARCHAR(64) PRIMARY KEY, jti_hash VARCHAR(64) NOT NULL, "
                "session_id VARCHAR(64) NOT NULL, worker_id VARCHAR(128) NOT NULL, "
                "subject_id VARCHAR(128) NOT NULL, expires_at DATETIME NOT NULL, "
                "redeemed_at DATETIME, revoked_at DATETIME, created_at DATETIME NOT NULL)"
            ))
            connection.execute(text(
                "INSERT INTO worker_authorization_tickets "
                "(ticket_id,jti_hash,session_id,worker_id,subject_id,expires_at,created_at) VALUES "
                "('legacy-a','jti-a','same-session','worker-a','owner','2030-01-01','2026-01-01'),"
                "('legacy-b','jti-b','same-session','worker-b','owner','2030-01-01','2026-01-01')"
            ))
        with pytest.raises(RuntimeError, match="duplicate session_id"):
            _ensure_worker_ticket_delivery_column(old_engine)
        with old_engine.connect() as connection:
            rows = connection.execute(text(
                "SELECT ticket_id FROM worker_authorization_tickets ORDER BY ticket_id"
            )).scalars().all()
            columns = {column["name"] for column in inspect(connection).get_columns(
                "worker_authorization_tickets"
            )}
        assert rows == ["legacy-a", "legacy-b"]
        # SQLite rolls the additive DDL and backfill back with the failed migration.
        assert "delivery_id_hash" not in columns
    finally:
        old_engine.dispose()


def test_worker_ticket_schema_upgrade_is_idempotent_and_preserves_rows():
    old_engine = create_engine("sqlite:///:memory:")
    try:
        with old_engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE worker_authorization_tickets ("
                "ticket_id VARCHAR(64) PRIMARY KEY, jti_hash VARCHAR(64) NOT NULL, "
                "session_id VARCHAR(64) NOT NULL, worker_id VARCHAR(128) NOT NULL, "
                "subject_id VARCHAR(128) NOT NULL, expires_at DATETIME NOT NULL, "
                "redeemed_at DATETIME, revoked_at DATETIME, created_at DATETIME NOT NULL)"
            ))
            connection.execute(text(
                "INSERT INTO worker_authorization_tickets "
                "(ticket_id,jti_hash,session_id,worker_id,subject_id,expires_at,created_at) VALUES "
                "('legacy-a','jti-a','session-a','worker-a','owner','2030-01-01','2026-01-01')"
            ))
        _ensure_worker_ticket_delivery_column(old_engine)
        _ensure_worker_ticket_delivery_column(old_engine)
        with old_engine.connect() as connection:
            values = connection.execute(text(
                "SELECT ticket_id, delivery_id_hash FROM worker_authorization_tickets"
            )).one()
            indexes = {index["name"] for index in inspect(connection).get_indexes(
                "worker_authorization_tickets"
            )}
        assert values.ticket_id == "legacy-a"
        assert values.delivery_id_hash == hashlib.sha256(b"legacy-ticket:legacy-a").hexdigest()
        assert {"uq_worker_ticket_delivery", "uq_worker_ticket_session"}.issubset(indexes)
    finally:
        old_engine.dispose()


def test_worker_ticket_schema_upgrade_resumes_after_column_addition_interruption():
    old_engine = create_engine("sqlite:///:memory:")
    try:
        with old_engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE worker_authorization_tickets ("
                "ticket_id VARCHAR(64) PRIMARY KEY, jti_hash VARCHAR(64) NOT NULL, "
                "delivery_id_hash VARCHAR(64), session_id VARCHAR(64) NOT NULL, "
                "worker_id VARCHAR(128) NOT NULL, subject_id VARCHAR(128) NOT NULL, "
                "expires_at DATETIME NOT NULL, redeemed_at DATETIME, revoked_at DATETIME, "
                "created_at DATETIME NOT NULL)"
            ))
            connection.execute(text(
                "INSERT INTO worker_authorization_tickets "
                "(ticket_id,jti_hash,session_id,worker_id,subject_id,expires_at,created_at) VALUES "
                "('interrupted','jti','session-a','worker-a','owner','2030-01-01','2026-01-01')"
            ))
        _ensure_worker_ticket_delivery_column(old_engine)
        with old_engine.connect() as connection:
            value = connection.execute(text(
                "SELECT delivery_id_hash FROM worker_authorization_tickets WHERE ticket_id='interrupted'"
            )).scalar_one()
        assert value == hashlib.sha256(b"legacy-ticket:interrupted").hexdigest()
    finally:
        old_engine.dispose()


def test_worker_ticket_schema_upgrade_rejects_duplicate_delivery_ids_without_deleting_rows():
    old_engine = create_engine("sqlite:///:memory:")
    try:
        with old_engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE worker_authorization_tickets ("
                "ticket_id VARCHAR(64) PRIMARY KEY, jti_hash VARCHAR(64) NOT NULL, "
                "delivery_id_hash VARCHAR(64), session_id VARCHAR(64) NOT NULL, "
                "worker_id VARCHAR(128) NOT NULL, subject_id VARCHAR(128) NOT NULL, "
                "expires_at DATETIME NOT NULL, redeemed_at DATETIME, revoked_at DATETIME, "
                "created_at DATETIME NOT NULL)"
            ))
            connection.execute(text(
                "INSERT INTO worker_authorization_tickets "
                "(ticket_id,jti_hash,delivery_id_hash,session_id,worker_id,subject_id,expires_at,created_at) VALUES "
                "('legacy-a','jti-a','same-delivery','session-a','worker-a','owner','2030-01-01','2026-01-01'),"
                "('legacy-b','jti-b','same-delivery','session-b','worker-a','owner','2030-01-01','2026-01-01')"
            ))
        with pytest.raises(RuntimeError, match="duplicate worker/delivery"):
            _ensure_worker_ticket_delivery_column(old_engine)
        with old_engine.connect() as connection:
            count = connection.execute(text(
                "SELECT COUNT(*) FROM worker_authorization_tickets"
            )).scalar_one()
        assert count == 2
    finally:
        old_engine.dispose()


def test_worker_ticket_retry_schema_upgrade_is_additive():
    old_engine = create_engine("sqlite:///:memory:")
    try:
        with old_engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE worker_authorization_tickets (ticket_id VARCHAR(64) PRIMARY KEY, "
                "jti_hash VARCHAR(64) NOT NULL, session_id VARCHAR(64) NOT NULL, "
                "worker_id VARCHAR(128) NOT NULL, subject_id VARCHAR(128) NOT NULL, "
                "expires_at DATETIME NOT NULL, redeemed_at DATETIME, revoked_at DATETIME, created_at DATETIME)"
            ))
            connection.execute(text(
                "INSERT INTO worker_authorization_tickets "
                "(ticket_id, jti_hash, session_id, worker_id, subject_id, expires_at) "
                "VALUES ('ticket-old', 'jti-hash', 'session-old', 'worker-old', 'owner', '2026-12-01')"
            ))
        _ensure_worker_ticket_delivery_column(old_engine)
        _ensure_worker_ticket_key_id_column(old_engine)
        columns = {column["name"] for column in inspect(old_engine).get_columns("worker_authorization_tickets")}
        assert {"delivery_id_hash", "key_id"}.issubset(columns)
        with old_engine.connect() as connection:
            row = connection.execute(text(
                "SELECT ticket_id, worker_id, delivery_id_hash FROM worker_authorization_tickets"
            )).one()
        assert row.ticket_id == "ticket-old"
        assert row.worker_id == "worker-old"
        assert len(row.delivery_id_hash) == 64
    finally:
        old_engine.dispose()


def test_worker_health_evidence_schema_upgrade_is_additive():
    old_engine = create_engine("sqlite:///:memory:")
    try:
        with old_engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE worker_health_records (worker_id VARCHAR(128) PRIMARY KEY, "
                "status VARCHAR(16) NOT NULL, observed_at DATETIME NOT NULL, sequence INTEGER NOT NULL, "
                "evidence_hash VARCHAR(64) NOT NULL, updated_at DATETIME NOT NULL)"
            ))
        _ensure_worker_health_evidence_columns(old_engine)
        columns = {column["name"] for column in inspect(old_engine).get_columns("worker_health_records")}
        assert {"evidence_payload", "signature_b64url"}.issubset(columns)
    finally:
        old_engine.dispose()
