"""PostgreSQL dialect-level lifecycle race tests.

These tests use only a random disposable schema in the explicitly configured test
database. They validate PostgreSQL locking/transaction semantics; they are not a
substitute for exercising the complete API and worker service against PostgreSQL.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, NoSuchModuleError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app.database import Base, BrowserSessionRecord, BrowserWorkerOperationRecord, WorkerIdentityRecord
from app.services.browser_session_manager import (
    BrowserPrincipal, BrowserSession, CleanupReceipt, SessionState, TerminationReceipt,
    InvalidSessionTransition, WorkerHealth, WorkerRegistration,
)
from app.services.worker_operation_store import DatabaseSupervisorOperationStore, OperationStoreError
from app.services.worker_supervisor import WorkerCommandAcknowledgement, WorkerSupervisorCoordinator


POSTGRES_URL = os.getenv("GUARD_AI_POSTGRES_TEST_URL", "")
pytestmark = pytest.mark.postgresql


@pytest.fixture
def pg_engine():
    if not POSTGRES_URL:
        pytest.skip("GUARD_AI_POSTGRES_TEST_URL is not configured")
    url = make_url(POSTGRES_URL)
    if url.get_backend_name() != "postgresql":
        pytest.skip("GUARD_AI_POSTGRES_TEST_URL must use a PostgreSQL URL")
    schema = f"guard_ai_test_{uuid.uuid4().hex}"
    try:
        admin = create_engine(url, pool_pre_ping=True)
    except (ImportError, ModuleNotFoundError, NoSuchModuleError):
        pytest.skip("No PostgreSQL SQLAlchemy driver is installed in the project environment")
    test_engine = None
    try:
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        scoped_url = url.update_query_dict({"options": f"-csearch_path={schema}"})
        test_engine = create_engine(scoped_url, pool_pre_ping=True)
        Base.metadata.create_all(bind=test_engine)
        with test_engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE worker_tickets (ticket_id text PRIMARY KEY, session_id text NOT NULL, "
                "redeemed boolean NOT NULL DEFAULT false, revoked boolean NOT NULL DEFAULT false)"
            ))
            connection.execute(text("CREATE TABLE audit_events (event_id text PRIMARY KEY, event_type text NOT NULL)"))
        yield test_engine
    finally:
        if test_engine is not None:
            test_engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()


def _seed(engine, *, state="AUTHORIZED", ticket=True):
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO browser_sessions "
                 "(session_id, owner_id, idempotency_key_hash, state, worker_id, policy_version, "
                 "created_at, authorized_at, updated_at) "
                 "VALUES ('s1', 'alice', 'pg-test-idem-key', :state, 'worker-1', 'pg-test-v1', "
                 "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"), {"state": state}
        )
        if ticket:
            connection.execute(text("INSERT INTO worker_tickets(ticket_id, session_id) VALUES ('t1', 's1')"))


def test_postgres_cancellation_serializes_with_ticket_issuance(pg_engine):
    _seed(pg_engine, ticket=False)
    issuance_locked = Event()
    allow_issue_commit = Event()

    def issue():
        with pg_engine.begin() as connection:
            session = connection.execute(text(
                "SELECT state FROM browser_sessions WHERE session_id='s1' FOR UPDATE"
            )).scalar_one()
            assert session == "AUTHORIZED"
            issuance_locked.set()
            assert allow_issue_commit.wait(5)
            connection.execute(text("INSERT INTO worker_tickets(ticket_id, session_id) VALUES ('t1', 's1')"))

    def cancel():
        assert issuance_locked.wait(5)
        with pg_engine.begin() as connection:
            connection.execute(text(
                "UPDATE browser_sessions SET state='CANCELLED' WHERE session_id='s1' AND state='AUTHORIZED'"
            ))
            connection.execute(text("UPDATE worker_tickets SET revoked=true WHERE session_id='s1'"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        issuer = pool.submit(issue)
        canceller = pool.submit(cancel)
        assert issuance_locked.wait(5)
        allow_issue_commit.set()
        issuer.result(timeout=10)
        canceller.result(timeout=10)
    with pg_engine.connect() as connection:
        state = connection.execute(text("SELECT state FROM browser_sessions WHERE session_id='s1'")).scalar_one()
        usable = connection.execute(text(
            "SELECT count(*) FROM worker_tickets WHERE session_id='s1' AND NOT revoked"
        )).scalar_one()
    assert state == "CANCELLED"
    assert usable == 0


def test_postgres_cancellation_serializes_with_ticket_redemption(pg_engine):
    _seed(pg_engine)
    redeem_locked = Event()
    allow_redeem_commit = Event()

    def redeem():
        with pg_engine.begin() as connection:
            state = connection.execute(text(
                "SELECT state FROM browser_sessions WHERE session_id='s1' FOR UPDATE"
            )).scalar_one()
            assert state == "AUTHORIZED"
            redeem_locked.set()
            assert allow_redeem_commit.wait(5)
            connection.execute(text("UPDATE worker_tickets SET redeemed=true WHERE ticket_id='t1' AND NOT revoked"))

    def cancel():
        assert redeem_locked.wait(5)
        with pg_engine.begin() as connection:
            connection.execute(text(
                "UPDATE browser_sessions SET state='CANCELLED' WHERE session_id='s1' AND state='AUTHORIZED'"
            ))
            connection.execute(text("UPDATE worker_tickets SET revoked=true WHERE session_id='s1'"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        redeemer = pool.submit(redeem)
        canceller = pool.submit(cancel)
        assert redeem_locked.wait(5)
        allow_redeem_commit.set()
        redeemer.result(timeout=10)
        canceller.result(timeout=10)
    with pg_engine.connect() as connection:
        state, revoked = connection.execute(text(
            "SELECT s.state, t.revoked FROM browser_sessions s JOIN worker_tickets t USING(session_id)"
        )).one()
    assert (state, revoked) == ("CANCELLED", True)


def test_postgres_cancel_first_blocks_later_ticket_issuance(pg_engine):
    _seed(pg_engine, ticket=False)
    cancel_locked = Event()
    allow_cancel_commit = Event()

    def cancel():
        with pg_engine.begin() as connection:
            connection.execute(text(
                "SELECT state FROM browser_sessions WHERE session_id='s1' FOR UPDATE"
            )).scalar_one()
            connection.execute(text(
                "UPDATE browser_sessions SET state='CANCELLED' WHERE session_id='s1'"
            ))
            cancel_locked.set()
            assert allow_cancel_commit.wait(5)

    def issue():
        assert cancel_locked.wait(5)
        with pg_engine.begin() as connection:
            state = connection.execute(text(
                "SELECT state FROM browser_sessions WHERE session_id='s1' FOR UPDATE"
            )).scalar_one()
            if state != "AUTHORIZED":
                return False
            connection.execute(text("INSERT INTO worker_tickets(ticket_id, session_id) VALUES ('t1', 's1')"))
            return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        canceller = pool.submit(cancel)
        issuer = pool.submit(issue)
        assert cancel_locked.wait(5)
        allow_cancel_commit.set()
        canceller.result(timeout=10)
        assert issuer.result(timeout=10) is False
    with pg_engine.connect() as connection:
        state, count = connection.execute(text(
            "SELECT state, (SELECT count(*) FROM worker_tickets) FROM browser_sessions WHERE session_id='s1'"
        )).one()
    assert (state, count) == ("CANCELLED", 0)


def test_postgres_concurrent_ticket_redemption_succeeds_once(pg_engine):
    _seed(pg_engine)
    from threading import Barrier

    barrier = Barrier(2)

    def redeem():
        with pg_engine.begin() as connection:
            barrier.wait(timeout=5)
            result = connection.execute(text(
                "UPDATE worker_tickets SET redeemed=true WHERE ticket_id='t1' AND NOT redeemed AND NOT revoked"
            ))
            return result.rowcount == 1

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: redeem(), range(2)))
    assert results.count(True) == 1
    assert results.count(False) == 1


def test_postgres_cancel_first_blocks_later_ticket_redemption(pg_engine):
    _seed(pg_engine)
    cancel_locked = Event()
    allow_cancel_commit = Event()

    def cancel():
        with pg_engine.begin() as connection:
            connection.execute(text(
                "SELECT state FROM browser_sessions WHERE session_id='s1' FOR UPDATE"
            )).scalar_one()
            connection.execute(text(
                "UPDATE browser_sessions SET state='CANCELLED' WHERE session_id='s1'"
            ))
            connection.execute(text("UPDATE worker_tickets SET revoked=true WHERE session_id='s1'"))
            cancel_locked.set()
            assert allow_cancel_commit.wait(5)

    def redeem():
        assert cancel_locked.wait(5)
        with pg_engine.begin() as connection:
            state = connection.execute(text(
                "SELECT state FROM browser_sessions WHERE session_id='s1' FOR UPDATE"
            )).scalar_one()
            if state != "AUTHORIZED":
                return False
            result = connection.execute(text(
                "UPDATE worker_tickets SET redeemed=true WHERE ticket_id='t1' AND NOT revoked AND NOT redeemed"
            ))
            return result.rowcount == 1

    with ThreadPoolExecutor(max_workers=2) as pool:
        canceller = pool.submit(cancel)
        redeemer = pool.submit(redeem)
        assert cancel_locked.wait(5)
        allow_cancel_commit.set()
        canceller.result(timeout=10)
        assert redeemer.result(timeout=10) is False
    with pg_engine.connect() as connection:
        state, redeemed, revoked = connection.execute(text(
            "SELECT s.state, t.redeemed, t.revoked FROM browser_sessions s "
            "JOIN worker_tickets t USING(session_id)"
        )).one()
    assert (state, redeemed, revoked) == ("CANCELLED", False, True)


def test_postgres_audit_failure_rolls_back_cancellation_and_ticket_revocation(pg_engine):
    _seed(pg_engine)
    with pytest.raises(SQLAlchemyError):
        with pg_engine.begin() as connection:
            connection.execute(text("UPDATE browser_sessions SET state='CANCELLED' WHERE session_id='s1'"))
            connection.execute(text("UPDATE worker_tickets SET revoked=true WHERE session_id='s1'"))
            # Deliberate constraint error stands in for audit persistence failure.
            connection.execute(text("INSERT INTO audit_events(event_id, event_type) VALUES ('a1', 'cancelled')"))
            connection.execute(text("INSERT INTO audit_events(event_id, event_type) VALUES ('a1', 'duplicate')"))
    with pg_engine.connect() as connection:
        state, revoked, audit_count = connection.execute(text(
            "SELECT s.state, t.revoked, (SELECT count(*) FROM audit_events) "
            "FROM browser_sessions s JOIN worker_tickets t USING(session_id)"
        )).one()
    assert (state, revoked, audit_count) == ("AUTHORIZED", False, 0)


def test_postgres_row_lock_timeout_fails_without_partial_state(pg_engine):
    _seed(pg_engine)
    lock_held = Event()
    release_lock = Event()

    def holder():
        with pg_engine.begin() as connection:
            connection.execute(text(
                "SELECT state FROM browser_sessions WHERE session_id='s1' FOR UPDATE"
            )).scalar_one()
            lock_held.set()
            assert release_lock.wait(5)

    def contender():
        assert lock_held.wait(5)
        with pg_engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text("SET LOCAL lock_timeout = '150ms'"))
                connection.execute(text(
                    "UPDATE browser_sessions SET state='CANCELLED' WHERE session_id='s1'"
                ))
                transaction.commit()
                return False
            except DBAPIError:
                transaction.rollback()
                return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        holding = pool.submit(holder)
        checking = pool.submit(contender)
        try:
            assert checking.result(timeout=5) is True
        finally:
            release_lock.set()
        holding.result(timeout=5)
    with pg_engine.connect() as connection:
        state, revoked = connection.execute(text(
            "SELECT s.state, t.revoked FROM browser_sessions s JOIN worker_tickets t USING(session_id)"
        )).one()
    assert (state, revoked) == ("AUTHORIZED", False)


class _PGTestSigner:
    def sign(self, command):
        from dataclasses import replace
        return replace(command, signing_key_id="pg-test-key", signature_b64url="test-only")


class _PGTestTransport:
    def authenticate_worker(self, expected_worker_id):
        return expected_worker_id

    def deliver_termination(self, command):
        return None


class _PGTestRegistry:
    def __init__(self, now):
        self.now = now

    def get_registration(self, worker_id):
        return WorkerRegistration(worker_id, WorkerHealth.HEALTHY, self.now, True)


class _PGTestVerifier:
    def verify_acknowledgement(self, acknowledgement, command):
        return acknowledgement.signature_b64url == "ack-test"

    def verify_termination_receipt(self, receipt, session):
        return receipt.signature_b64url == "termination-test"

    def verify_cleanup_receipt(self, receipt, session):
        return receipt.signature_b64url == "cleanup-test"


def _pg_active_session(pg_engine):
    now = datetime.now(timezone.utc)
    session_id = f"pg-{uuid.uuid4().hex}"
    owner_id = "pg-test-owner"
    session_factory = sessionmaker(bind=pg_engine, expire_on_commit=False)
    db = session_factory()
    try:
        db.add(BrowserSessionRecord(
            session_id=session_id,
            owner_id=owner_id,
            idempotency_key_hash=uuid.uuid4().hex,
            state=SessionState.ACTIVE.value,
            worker_id="pg-worker-1",
            policy_version="pg-test-v1",
            created_at=now,
            authorized_at=now,
            updated_at=now,
        ))
        db.add(WorkerIdentityRecord(
            worker_id="pg-worker-1",
            certificate_fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
            certificate_pem="test-only-certificate",
            certificate_chain_pem="test-only-certificate-chain",
            certificate_expires_at=now + timedelta(days=1),
            status="ACTIVE",
            registered_by="pg-test-adapter",
            registered_at=now,
        ))
        db.commit()
    finally:
        db.close()
    domain = BrowserSession(session_id, owner_id, SessionState.ACTIVE, "pg-worker-1")
    return session_factory, domain, now


def _pg_request(session_factory, session, now):
    evidence_verifier = _PGTestVerifier()
    store = DatabaseSupervisorOperationStore(
        session_factory,
        clock=lambda: now,
        message_verifier=evidence_verifier,
        cleanup_verifier=evidence_verifier,
    )
    coordinator = WorkerSupervisorCoordinator(clock=lambda: now, signer=_PGTestSigner())
    pending, command = coordinator.request_termination(
        session,
        principal=BrowserPrincipal(session.owner_id, frozenset({"sandbox:write"})),
        registry=_PGTestRegistry(now),
        store=store,
        transport=_PGTestTransport(),
    )
    return pending, command, store, coordinator


def test_postgres_concurrent_termination_requests_create_one_durable_command(pg_engine):
    session_factory, session, now = _pg_active_session(pg_engine)

    def request():
        try:
            return _pg_request(session_factory, session, now)[1].command_id
        except OperationStoreError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: request(), range(2)))
    assert sum(result is not None for result in results) == 1
    db = session_factory()
    try:
        saved_session = db.query(BrowserSessionRecord).filter_by(session_id=session.session_id).one()
        operations = db.query(BrowserWorkerOperationRecord).filter_by(session_id=session.session_id).all()
        assert saved_session.state == SessionState.TERMINATION_PENDING.value
        assert len(operations) == 1
    finally:
        db.close()


def test_postgres_duplicate_ack_receipt_and_restart_recovery(pg_engine):
    session_factory, session, now = _pg_active_session(pg_engine)
    pending, command, _, coordinator = _pg_request(session_factory, session, now)
    verifier = _PGTestVerifier()
    restarted_store = DatabaseSupervisorOperationStore(
        session_factory,
        clock=lambda: now,
        message_verifier=verifier,
        cleanup_verifier=verifier,
    )
    assert any(
        item["operation_id"] == command.command_id
        for item in restarted_store.recoverable_operations()
    )
    acknowledgement = WorkerCommandAcknowledgement(
        command.command_id, session.session_id, session.worker_id, True, now, "ack-test"
    )
    coordinator.accept_acknowledgement(pending, acknowledgement, store=restarted_store, verifier=verifier)
    with pytest.raises(InvalidSessionTransition, match="already recorded"):
        coordinator.accept_acknowledgement(pending, acknowledgement, store=restarted_store, verifier=verifier)
    receipt = TerminationReceipt(
        session.session_id, session.worker_id, command.command_id, True, now,
        signature_b64url="termination-test",
    )
    terminated = coordinator.accept_termination_receipt(
        pending, receipt, store=restarted_store, verifier=verifier
    )
    with pytest.raises(InvalidSessionTransition, match="already consumed"):
        coordinator.accept_termination_receipt(pending, receipt, store=restarted_store, verifier=verifier)
    cleanup_pending = coordinator.begin_cleanup(terminated, store=restarted_store)
    cleanup = CleanupReceipt(
        session.session_id, session.worker_id, True, now,
        signature_b64url="cleanup-test", operation_id=command.command_id,
        runtime_terminated=True, temporary_storage_removed=True,
        session_data_removed=True, credentials_disposed=True,
        temporary_artifacts_removed=True,
    )
    coordinator.verify_cleanup(cleanup_pending, cleanup, verifier=verifier, store=restarted_store)
    db = session_factory()
    try:
        persisted = db.query(BrowserSessionRecord).filter_by(session_id=session.session_id).one()
        assert persisted.state == SessionState.CLEANUP_VERIFIED.value
    finally:
        db.close()
