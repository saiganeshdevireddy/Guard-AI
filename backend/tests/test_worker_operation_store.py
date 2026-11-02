from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import secrets

import pytest

from app.database import (
    BrowserSessionRecord, BrowserWorkerOperationRecord, SessionLocal,
    WorkerIdentityRecord, init_db,
)
from app.services.browser_session_manager import (
    BrowserPrincipal,
    BrowserSession,
    CleanupReceipt,
    InvalidSessionTransition,
    SessionState,
    TerminationReceipt,
    WorkerHealth,
    WorkerRegistration,
)
from app.services.worker_operation_store import DatabaseSupervisorOperationStore, OperationStoreError
from app.services.worker_supervisor import WorkerCommandAcknowledgement, WorkerSupervisorCoordinator


init_db()
NOW = datetime.now(timezone.utc)


class TestOnlyRegistry:
    def get_registration(self, worker_id):
        return WorkerRegistration(worker_id, WorkerHealth.UNHEALTHY, NOW, True)


class TestOnlySigner:
    def sign(self, command):
        from dataclasses import replace
        return replace(command, signing_key_id="test-key", signature_b64url="test-signature")


class TestOnlyTransport:
    def authenticate_worker(self, expected_worker_id):
        return expected_worker_id

    def deliver_termination(self, command):
        return None


class TestOnlyEvidenceVerifier:
    def verify(self, command, *, now):
        return command.signing_key_id == "test-key" and command.signature_b64url == "test-signature"

    def verify_acknowledgement(self, acknowledgement, command):
        return acknowledgement.signature_b64url == "ack-test-signature"

    def verify_termination_receipt(self, receipt, session):
        return receipt.signature_b64url == "termination-test-signature"

    def verify_cleanup_receipt(self, receipt, session):
        return receipt.signature_b64url == "cleanup-test-signature" and receipt.resources_absent


def _store(session_factory=SessionLocal):
    verifier = TestOnlyEvidenceVerifier()
    return DatabaseSupervisorOperationStore(
        session_factory,
        clock=lambda: NOW,
        command_verifier=verifier,
        message_verifier=verifier,
        cleanup_verifier=verifier,
    )


def _seed_active_session():
    session_id = secrets.token_urlsafe(24)
    owner_id = f"operation-test-{secrets.token_hex(5)}"
    worker_id = f"worker-operation-{secrets.token_hex(5)}"
    db = SessionLocal()
    try:
        db.add(BrowserSessionRecord(
            session_id=session_id,
            owner_id=owner_id,
            idempotency_key_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
            state=SessionState.ACTIVE.value,
            worker_id=worker_id,
            policy_version="test-policy-v1",
            authorized_at=NOW,
            updated_at=NOW,
        ))
        db.add(WorkerIdentityRecord(
            worker_id=worker_id,
            certificate_fingerprint=secrets.token_hex(32),
            certificate_pem="test-only-certificate",
            certificate_chain_pem="test-only-certificate-chain",
            certificate_expires_at=NOW + timedelta(days=1),
            status="ACTIVE",
            registered_by="unit-test-adapter",
            registered_at=NOW,
        ))
        db.commit()
    finally:
        db.close()
    return BrowserSession(session_id, owner_id, SessionState.ACTIVE, worker_id)


def _coordinator():
    return WorkerSupervisorCoordinator(clock=lambda: NOW, signer=TestOnlySigner())


def _request(session, store):
    return _coordinator().request_termination(
        session,
        principal=BrowserPrincipal(session.owner_id, frozenset({"sandbox:write"})),
        registry=TestOnlyRegistry(),
        store=store,
        transport=TestOnlyTransport(),
    )


def _assert_saved_state(session_id, expected):
    db = SessionLocal()
    try:
        return db.query(BrowserSessionRecord).filter_by(session_id=session_id).one().state == expected
    finally:
        db.close()


def test_operation_and_pending_state_survive_store_restart():
    session = _seed_active_session()
    first_store = _store()
    pending, command = _request(session, first_store)
    restarted_store = _store()

    restored_command = restarted_store.get(command.command_id)
    recoverable = restarted_store.recoverable_operations()
    assert restored_command == command
    assert _assert_saved_state(session.session_id, SessionState.TERMINATION_PENDING.value)
    assert any(item["operation_id"] == command.command_id for item in recoverable)
    assert pending.state is SessionState.TERMINATION_PENDING


def test_acknowledgement_is_separate_from_termination_and_replay_is_rejected():
    session = _seed_active_session()
    store = _store()
    pending, command = _request(session, store)
    coordinator = _coordinator()
    verifier = TestOnlyEvidenceVerifier()
    acknowledgement = WorkerCommandAcknowledgement(
        command.command_id, session.session_id, session.worker_id, True, NOW, "ack-test-signature"
    )

    coordinator.accept_acknowledgement(pending, acknowledgement, store=store, verifier=verifier)
    db = SessionLocal()
    try:
        record = db.query(BrowserWorkerOperationRecord).filter_by(operation_id=command.command_id).one()
        assert record.acknowledgement_status == "ACCEPTED"
        assert record.termination_status == "PENDING"
        assert record.termination_evidence_verified is False
        assert db.query(BrowserSessionRecord).filter_by(session_id=session.session_id).one().state == "TERMINATION_PENDING"
    finally:
        db.close()
    with pytest.raises(InvalidSessionTransition, match="already recorded"):
        coordinator.accept_acknowledgement(pending, acknowledgement, store=store, verifier=verifier)


def test_signed_termination_receipt_and_cleanup_commit_atomically():
    session = _seed_active_session()
    store = _store()
    coordinator = _coordinator()
    pending, command = _request(session, store)
    verifier = TestOnlyEvidenceVerifier()
    acknowledgement = WorkerCommandAcknowledgement(
        command.command_id, session.session_id, session.worker_id, True, NOW, "ack-test-signature"
    )
    coordinator.accept_acknowledgement(pending, acknowledgement, store=store, verifier=verifier)
    termination_receipt = TerminationReceipt(
        session.session_id, session.worker_id, command.command_id, True, NOW,
        signature_b64url="termination-test-signature",
    )
    terminated = coordinator.accept_termination_receipt(
        pending, termination_receipt, store=store, verifier=verifier
    )
    cleanup_pending = coordinator.begin_cleanup(terminated, store=store)
    cleanup_receipt = CleanupReceipt(
        session.session_id, session.worker_id, True, NOW,
        signature_b64url="cleanup-test-signature", operation_id=command.command_id,
        runtime_terminated=True, temporary_storage_removed=True,
        session_data_removed=True, credentials_disposed=True,
        temporary_artifacts_removed=True,
    )
    cleaned = coordinator.verify_cleanup(
        cleanup_pending, cleanup_receipt, verifier=verifier, store=store
    )
    assert cleaned.state is SessionState.CLEANUP_VERIFIED
    assert _assert_saved_state(session.session_id, SessionState.CLEANUP_VERIFIED.value)
    db = SessionLocal()
    try:
        record = db.query(BrowserWorkerOperationRecord).filter_by(operation_id=command.command_id).one()
        assert record.termination_evidence_verified is True
        assert record.cleanup_evidence_verified is True
        assert record.cleanup_status == "VERIFIED"
        assert "temporary_artifacts_removed" in record.cleanup_evidence_json
    finally:
        db.close()


def test_cleanup_failure_and_retry_survive_store_restart():
    session = _seed_active_session()
    store = _store()
    pending, command = _request(session, store)
    coordinator = _coordinator()
    verifier = TestOnlyEvidenceVerifier()
    coordinator.accept_acknowledgement(
        pending,
        WorkerCommandAcknowledgement(
            command.command_id, session.session_id, session.worker_id, True, NOW, "ack-test-signature"
        ),
        store=store,
        verifier=verifier,
    )
    terminated = coordinator.accept_termination_receipt(
        pending,
        TerminationReceipt(
            session.session_id, session.worker_id, command.command_id, True, NOW,
            signature_b64url="termination-test-signature",
        ),
        store=store,
        verifier=verifier,
    )
    cleanup_pending = coordinator.begin_cleanup(terminated, store=store)
    failed = coordinator.record_cleanup_failure(cleanup_pending, store=store)
    retried = coordinator.retry_cleanup(failed, store=_store())

    assert retried.state is SessionState.CLEANUP_PENDING
    assert _assert_saved_state(session.session_id, SessionState.CLEANUP_PENDING.value)
    records = _store().recoverable_operations()
    assert any(item["operation_id"] == command.command_id and item["status"] == "CLEANUP_PENDING" for item in records)


def test_stale_snapshot_cannot_create_second_durable_termination_operation():
    session = _seed_active_session()
    store = _store()
    _request(session, store)
    with pytest.raises(OperationStoreError):
        _request(session, store)


def test_store_database_failure_fails_closed_without_state_update():
    session = _seed_active_session()

    def failing_factory():
        raise RuntimeError("simulated database outage")

    store = DatabaseSupervisorOperationStore(failing_factory, clock=lambda: NOW)
    with pytest.raises(RuntimeError):
        _request(session, store)
    assert _assert_saved_state(session.session_id, SessionState.ACTIVE.value)


def test_cleanup_retries_are_bounded_and_leave_explicit_failure_state():
    session = _seed_active_session()
    store = _store()
    coordinator = _coordinator()
    pending, command = _request(session, store)
    verifier = TestOnlyEvidenceVerifier()
    coordinator.accept_acknowledgement(
        pending,
        WorkerCommandAcknowledgement(
            command.command_id, session.session_id, session.worker_id, True, NOW, "ack-test-signature"
        ),
        store=store,
        verifier=verifier,
    )
    terminated = coordinator.accept_termination_receipt(
        pending,
        TerminationReceipt(
            session.session_id, session.worker_id, command.command_id, True, NOW,
            signature_b64url="termination-test-signature",
        ),
        store=store,
        verifier=verifier,
    )
    cleanup_pending = coordinator.begin_cleanup(terminated, store=store)
    for _ in range(2):
        failed = coordinator.record_cleanup_failure(cleanup_pending, store=store)
        cleanup_pending = coordinator.retry_cleanup(failed, store=store)
    failed = coordinator.record_cleanup_failure(cleanup_pending, store=store)
    with pytest.raises(InvalidSessionTransition, match="retry could not be persisted"):
        coordinator.retry_cleanup(failed, store=store)
    assert _assert_saved_state(session.session_id, SessionState.CLEANUP_FAILED.value)


def test_default_message_verifier_rejects_test_signature_at_durable_boundary():
    session = _seed_active_session()
    test_store = _store()
    pending, command = _request(session, test_store)
    ack = WorkerCommandAcknowledgement(
        command.command_id, session.session_id, session.worker_id, True, NOW, "ack-test-signature"
    )
    coordinator = _coordinator()
    with pytest.raises(InvalidSessionTransition, match="already recorded"):
        coordinator.accept_acknowledgement(
            pending,
            ack,
            store=DatabaseSupervisorOperationStore(SessionLocal, clock=lambda: NOW),
            verifier=TestOnlyEvidenceVerifier(),
        )
    db = SessionLocal()
    try:
        operation = db.query(BrowserWorkerOperationRecord).filter_by(operation_id=command.command_id).one()
        assert operation.acknowledgement_status == "PENDING"
        assert operation.status == "DELIVERED"
    finally:
        db.close()


def test_cleanup_without_independent_verifier_cannot_be_persisted_as_verified():
    session = _seed_active_session()
    store = _store()
    coordinator = _coordinator()
    pending, command = _request(session, store)
    verifier = TestOnlyEvidenceVerifier()
    coordinator.accept_acknowledgement(
        pending,
        WorkerCommandAcknowledgement(
            command.command_id, session.session_id, session.worker_id, True, NOW, "ack-test-signature"
        ),
        store=store,
        verifier=verifier,
    )
    terminated = coordinator.accept_termination_receipt(
        pending,
        TerminationReceipt(
            session.session_id, session.worker_id, command.command_id, True, NOW,
            signature_b64url="termination-test-signature",
        ),
        store=store,
        verifier=verifier,
    )
    cleanup_pending = coordinator.begin_cleanup(terminated, store=store)
    receipt = CleanupReceipt(
        session.session_id, session.worker_id, True, NOW,
        signature_b64url="cleanup-test-signature", operation_id=command.command_id,
        runtime_terminated=True, temporary_storage_removed=True,
        session_data_removed=True, credentials_disposed=True,
        temporary_artifacts_removed=True,
    )
    no_cleanup_verifier_store = DatabaseSupervisorOperationStore(
        SessionLocal, clock=lambda: NOW, message_verifier=verifier
    )
    with pytest.raises(InvalidSessionTransition, match="could not be persisted"):
        coordinator.verify_cleanup(
            cleanup_pending, receipt, verifier=verifier, store=no_cleanup_verifier_store
        )
    assert _assert_saved_state(session.session_id, SessionState.CLEANUP_PENDING.value)


@pytest.mark.parametrize("mutation", ["wrong_operation", "stale", "future", "missing_artifact"])
def test_cleanup_evidence_must_match_operation_be_fresh_and_cover_all_resources(mutation):
    session = _seed_active_session()
    store = _store()
    coordinator = _coordinator()
    pending, command = _request(session, store)
    verifier = TestOnlyEvidenceVerifier()
    coordinator.accept_acknowledgement(
        pending,
        WorkerCommandAcknowledgement(
            command.command_id, session.session_id, session.worker_id, True, NOW, "ack-test-signature"
        ),
        store=store,
        verifier=verifier,
    )
    terminated = coordinator.accept_termination_receipt(
        pending,
        TerminationReceipt(
            session.session_id, session.worker_id, command.command_id, True, NOW,
            signature_b64url="termination-test-signature",
        ),
        store=store,
        verifier=verifier,
    )
    cleanup_pending = coordinator.begin_cleanup(terminated, store=store)
    values = {
        "session_id": session.session_id,
        "worker_id": session.worker_id,
        "resources_absent": True,
        "verified_at": NOW,
        "signature_b64url": "cleanup-test-signature",
        "operation_id": command.command_id,
        "runtime_terminated": True,
        "temporary_storage_removed": True,
        "session_data_removed": True,
        "credentials_disposed": True,
        "temporary_artifacts_removed": True,
    }
    if mutation == "wrong_operation":
        values["operation_id"] = "another-operation"
    elif mutation == "stale":
        values["verified_at"] = NOW - timedelta(seconds=31)
    elif mutation == "future":
        values["verified_at"] = NOW + timedelta(seconds=1)
    elif mutation == "missing_artifact":
        values["temporary_artifacts_removed"] = False
    receipt = CleanupReceipt(**values)

    with pytest.raises(InvalidSessionTransition):
        coordinator.verify_cleanup(cleanup_pending, receipt, verifier=verifier, store=store)
    assert _assert_saved_state(session.session_id, SessionState.CLEANUP_PENDING.value)


def test_default_command_verifier_rejects_unconfigured_signatures_before_persisting():
    session = _seed_active_session()
    store = DatabaseSupervisorOperationStore(SessionLocal, clock=lambda: NOW)
    with pytest.raises(OperationStoreError, match="could not be stored"):
        _request(session, store)
    assert _assert_saved_state(session.session_id, SessionState.ACTIVE.value)
