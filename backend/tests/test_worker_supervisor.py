from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
from app.services.worker_supervisor import (
    AsymmetricWorkerCommandSigner,
    WorkerCommandAcknowledgement,
    WorkerSupervisorCoordinator,
    verify_signed_worker_command,
)


class OnlyForTestsOperationStore:
    """In-memory adapter for unit tests; not a production persistence layer."""

    def __init__(self):
        self.commands = {}
        self.consumed = set()
        self.acknowledged = set()
        self.sessions = set()
        self.session_states = {}
        self.active_commands = {}
        self.lock = Lock()

    def put(self, command, expected, pending):
        with self.lock:
            current = self.session_states.get(command.session_id, expected)
            active_id = self.active_commands.get(command.session_id)
            active = self.commands.get(active_id) if active_id else None
            if (command.command_id in self.commands or current != expected
                    or current.state not in {
                        SessionState.ACTIVE, SessionState.STOPPING, SessionState.TERMINATION_PENDING
                    }
                    or (active is not None and active.expires_at > command.issued_at)):
                raise ValueError("duplicate pending command")
            self.session_states[command.session_id] = pending
            self.active_commands[command.session_id] = command.command_id
            self.commands[command.command_id] = command

    def get(self, command_id):
        with self.lock:
            return self.commands.get(command_id)

    def begin_delivery_attempt(self, command_id, now):
        with self.lock:
            command = self.commands.get(command_id)
            if command is None or command_id in self.consumed:
                return False
            self.attempts = getattr(self, "attempts", {})
            self.attempts[command_id] = self.attempts.get(command_id, 0) + 1
            return self.attempts[command_id] <= 3

    def mark_delivered(self, command_id, now):
        return command_id in self.commands and command_id not in self.consumed

    def record_acknowledgement(self, command_id, acknowledgement):
        with self.lock:
            if command_id not in self.commands or command_id in self.acknowledged:
                return False
            self.acknowledged.add(command_id)
            return True

    def has_acknowledgement(self, command_id):
        with self.lock:
            return command_id in self.acknowledged

    def consume_result(self, command_id, expected, terminated, receipt):
        with self.lock:
            command = self.commands.get(command_id)
            if (command is None or command_id in self.consumed
                    or self.session_states.get(command.session_id) != expected
                    or terminated.state is not SessionState.TERMINATED):
                return False
            self.consumed.add(command_id)
            self.session_states[command.session_id] = terminated
            self.active_commands.pop(command.session_id, None)
            return True

    def begin_cleanup(self, expected, pending):
        with self.lock:
            if self.session_states.get(expected.session_id) != expected:
                return False
            self.session_states[expected.session_id] = pending
            return True

    def commit_cleanup(self, expected, cleaned, receipt):
        with self.lock:
            if self.session_states.get(expected.session_id) != expected:
                return False
            self.session_states[expected.session_id] = cleaned
            return True

    def record_cleanup_failure(self, expected, failed):
        return self.begin_cleanup(expected, failed)

    def retry_cleanup(self, expected, pending):
        return self.begin_cleanup(expected, pending)


class OnlyForTestsRegistry:
    def __init__(self, registration):
        self.registration = registration

    def get_registration(self, worker_id):
        return self.registration


class OnlyForTestsTransport:
    def __init__(self, *, fail=False, authenticated_worker="worker-1"):
        self.commands = []
        self.fail = fail
        self.authenticated_worker = authenticated_worker

    def authenticate_worker(self, expected_worker_id):
        return self.authenticated_worker

    def deliver_termination(self, command):
        if self.fail:
            raise TimeoutError("test transport timeout")
        self.commands.append(command)


class OnlyForTestsVerifier:
    def __init__(self, *, accepted=True):
        self.accepted = accepted

    def verify_termination_receipt(self, receipt, session):
        return self.accepted

    def verify_acknowledgement(self, acknowledgement, command):
        return self.accepted


class OnlyForTestsCleanupVerifier:
    def verify_cleanup_receipt(self, receipt, session):
        return all((
            receipt.resources_absent,
            receipt.runtime_terminated,
            receipt.temporary_storage_removed,
            receipt.session_data_removed,
            receipt.credentials_disposed,
            receipt.temporary_artifacts_removed,
        ))


class OnlyForTestsCommandSigner:
    def sign(self, command):
        from dataclasses import replace
        return replace(command, signing_key_id="unit-test", signature_b64url="test-only-signature")


def test_asymmetric_command_signing_authenticates_all_command_fields():
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    signer = AsymmetricWorkerCommandSigner(pem, "control-key-1")
    now = datetime.now(timezone.utc)
    from app.services.worker_supervisor import TerminationCommand
    command = signer.sign(TerminationCommand(
        "op-1", "session-1", "worker-1", "alice", now, now + timedelta(seconds=30)
    ))
    public_keys = {"control-key-1": private_key.public_key()}
    assert verify_signed_worker_command(
        command, public_keys, expected_worker_id="worker-1", now=now
    ) is True

    tampered = __import__("dataclasses").replace(command, worker_id="worker-attacker")
    assert verify_signed_worker_command(
        tampered, public_keys, expected_worker_id="worker-1", now=now
    ) is False
    assert verify_signed_worker_command(
        command, public_keys, expected_worker_id="worker-1", now=command.expires_at
    ) is False


@pytest.fixture
def setup_supervisor(now):
    coordinator = WorkerSupervisorCoordinator(clock=lambda: now, signer=OnlyForTestsCommandSigner())
    session = BrowserSession("session-1", "alice", SessionState.ACTIVE, "worker-1")
    registration = WorkerRegistration("worker-1", WorkerHealth.UNHEALTHY, now, True)
    store = OnlyForTestsOperationStore()
    transport = OnlyForTestsTransport()
    principal = BrowserPrincipal("alice", frozenset({"sandbox:write"}))
    pending, command = coordinator.request_termination(
        session, principal=principal, registry=OnlyForTestsRegistry(registration),
        store=store, transport=transport,
    )
    return coordinator, pending, command, store, transport


@pytest.fixture
def now():
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_termination_request_is_owner_authorized_bounded_and_remains_pending(setup_supervisor, now):
    _, pending, command, _, transport = setup_supervisor
    assert pending.state is SessionState.TERMINATION_PENDING
    assert command in transport.commands
    assert command.expires_at - command.issued_at == timedelta(seconds=30)
    assert command.session_id == pending.session_id
    assert pending.state is not SessionState.TERMINATED


def test_wrong_owner_cannot_request_termination(now):
    coordinator = WorkerSupervisorCoordinator(clock=lambda: now, signer=OnlyForTestsCommandSigner())
    session = BrowserSession("session-1", "alice", SessionState.ACTIVE, "worker-1")
    with pytest.raises(PermissionError):
        coordinator.request_termination(
            session,
            principal=BrowserPrincipal("bob", frozenset({"sandbox:write"})),
            registry=OnlyForTestsRegistry(WorkerRegistration("worker-1", WorkerHealth.HEALTHY, now, True)),
            store=OnlyForTestsOperationStore(),
            transport=OnlyForTestsTransport(),
        )


def test_unknown_or_stale_worker_registration_fails_closed(now):
    coordinator = WorkerSupervisorCoordinator(clock=lambda: now, signer=OnlyForTestsCommandSigner())
    session = BrowserSession("session-1", "alice", SessionState.ACTIVE, "worker-1")
    for registration in (
        None,
        WorkerRegistration("worker-1", WorkerHealth.UNKNOWN, now, True),
        WorkerRegistration("worker-1", WorkerHealth.HEALTHY, now - timedelta(minutes=2), True),
        WorkerRegistration("other-worker", WorkerHealth.HEALTHY, now, True),
        WorkerRegistration("worker-1", WorkerHealth.HEALTHY, now, False),
    ):
        with pytest.raises(RuntimeError, match="unverified"):
            coordinator.request_termination(
                session,
                principal=BrowserPrincipal("alice", frozenset({"sandbox:write"})),
                registry=OnlyForTestsRegistry(registration),
                store=OnlyForTestsOperationStore(),
                transport=OnlyForTestsTransport(),
            )


def test_mismatched_worker_channel_identity_is_rejected_without_claiming_delivery(now):
    coordinator = WorkerSupervisorCoordinator(clock=lambda: now, signer=OnlyForTestsCommandSigner())
    session = BrowserSession("session-1", "alice", SessionState.ACTIVE, "worker-1")
    store = OnlyForTestsOperationStore()
    with pytest.raises(RuntimeError, match="identity does not match"):
        coordinator.request_termination(
            session,
            principal=BrowserPrincipal("alice", frozenset({"sandbox:write"})),
            registry=OnlyForTestsRegistry(WorkerRegistration("worker-1", WorkerHealth.HEALTHY, now, True)),
            store=store,
            transport=OnlyForTestsTransport(authenticated_worker="worker-attacker"),
        )
    assert len(store.commands) == 1
    assert next(iter(store.session_states.values())).state is SessionState.TERMINATION_PENDING


def test_transport_timeout_never_reports_termination(now):
    coordinator = WorkerSupervisorCoordinator(clock=lambda: now, signer=OnlyForTestsCommandSigner())
    session = BrowserSession("session-1", "alice", SessionState.ACTIVE, "worker-1")
    store = OnlyForTestsOperationStore()
    with pytest.raises(TimeoutError):
        coordinator.request_termination(
            session,
            principal=BrowserPrincipal("alice", frozenset({"sandbox:write"})),
            registry=OnlyForTestsRegistry(WorkerRegistration("worker-1", WorkerHealth.HEALTHY, now, True)),
            store=store,
            transport=OnlyForTestsTransport(fail=True),
        )
    assert next(iter(store.session_states.values())).state is SessionState.TERMINATION_PENDING


def test_repeated_termination_request_from_stale_snapshot_is_rejected(setup_supervisor, now):
    coordinator, pending, _, store, transport = setup_supervisor
    original = BrowserSession("session-1", "alice", SessionState.ACTIVE, "worker-1")
    with pytest.raises(ValueError, match="duplicate pending command"):
        coordinator.request_termination(
            original,
            principal=BrowserPrincipal("alice", frozenset({"sandbox:write"})),
            registry=OnlyForTestsRegistry(WorkerRegistration("worker-1", WorkerHealth.UNHEALTHY, now, True)),
            store=store,
            transport=transport,
        )
    assert store.session_states["session-1"] == pending


def test_expired_termination_command_can_be_retried_with_a_new_id(now):
    clock_value = [now]
    coordinator = WorkerSupervisorCoordinator(clock=lambda: clock_value[0], signer=OnlyForTestsCommandSigner())
    session = BrowserSession("session-1", "alice", SessionState.ACTIVE, "worker-1")
    principal = BrowserPrincipal("alice", frozenset({"sandbox:write"}))
    registry = OnlyForTestsRegistry(WorkerRegistration("worker-1", WorkerHealth.UNHEALTHY, now, True))
    store = OnlyForTestsOperationStore()
    transport = OnlyForTestsTransport()
    pending, first_command = coordinator.request_termination(
        session, principal=principal, registry=registry, store=store, transport=transport
    )

    clock_value[0] = now + timedelta(seconds=31)
    registry.registration = WorkerRegistration("worker-1", WorkerHealth.UNHEALTHY, clock_value[0], True)
    retried, second_command = coordinator.request_termination(
        pending, principal=principal, registry=registry, store=store, transport=transport
    )
    assert retried.state is SessionState.TERMINATION_PENDING
    assert second_command.command_id != first_command.command_id
    assert len(transport.commands) == 2


def test_termination_requires_verified_nonreplayed_unexpired_receipt(setup_supervisor, now):
    coordinator, pending, command, store, _ = setup_supervisor
    coordinator.accept_acknowledgement(
        pending,
        WorkerCommandAcknowledgement(command.command_id, command.session_id, command.worker_id, True, now),
        store=store,
        verifier=OnlyForTestsVerifier(),
    )
    receipt = TerminationReceipt("session-1", "worker-1", command.command_id, True, now)
    terminated = coordinator.accept_termination_receipt(
        pending, receipt, store=store, verifier=OnlyForTestsVerifier()
    )
    assert terminated.state is SessionState.TERMINATED
    with pytest.raises(InvalidSessionTransition, match="already consumed"):
        coordinator.accept_termination_receipt(
            pending, receipt, store=store, verifier=OnlyForTestsVerifier()
        )


def test_concurrent_termination_receipt_replay_is_consumed_exactly_once(setup_supervisor, now):
    coordinator, pending, command, store, _ = setup_supervisor
    coordinator.accept_acknowledgement(
        pending,
        WorkerCommandAcknowledgement(command.command_id, command.session_id, command.worker_id, True, now),
        store=store,
        verifier=OnlyForTestsVerifier(),
    )
    receipt = TerminationReceipt("session-1", "worker-1", command.command_id, True, now)
    barrier = Barrier(2)

    def accept():
        barrier.wait(timeout=3)
        try:
            coordinator.accept_termination_receipt(
                pending, receipt, store=store, verifier=OnlyForTestsVerifier()
            )
            return True
        except InvalidSessionTransition:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: accept(), range(2)))
    assert results.count(True) == 1
    assert results.count(False) == 1


def test_invalid_worker_receipt_cannot_advance_or_consume_command(setup_supervisor, now):
    coordinator, pending, command, store, _ = setup_supervisor
    coordinator.accept_acknowledgement(
        pending,
        WorkerCommandAcknowledgement(command.command_id, command.session_id, command.worker_id, True, now),
        store=store,
        verifier=OnlyForTestsVerifier(),
    )
    receipt = TerminationReceipt("session-1", "worker-1", command.command_id, True, now)
    with pytest.raises(InvalidSessionTransition, match="could not be verified"):
        coordinator.accept_termination_receipt(
            pending, receipt, store=store, verifier=OnlyForTestsVerifier(accepted=False)
        )
    assert command.command_id not in store.consumed


def test_expired_and_mismatched_receipts_fail_closed(setup_supervisor, now):
    coordinator, pending, command, store, _ = setup_supervisor
    receipt = TerminationReceipt("session-1", "worker-1", command.command_id, True, now)
    expired = TerminationReceipt("session-1", "worker-1", command.command_id, True, now + timedelta(seconds=31))
    with pytest.raises(InvalidSessionTransition, match="expired or mismatched"):
        coordinator.accept_termination_receipt(pending, expired, store=store, verifier=OnlyForTestsVerifier())
    mismatched = TerminationReceipt("other", "worker-1", command.command_id, True, now)
    with pytest.raises(InvalidSessionTransition, match="expired or mismatched"):
        coordinator.accept_termination_receipt(pending, mismatched, store=store, verifier=OnlyForTestsVerifier())
    not_terminated = TerminationReceipt("session-1", "worker-1", command.command_id, False, now)
    with pytest.raises(InvalidSessionTransition, match="expired or mismatched"):
        coordinator.accept_termination_receipt(pending, not_terminated, store=store, verifier=OnlyForTestsVerifier())

    wrong_owner = BrowserSession("session-1", "mallory", SessionState.TERMINATION_PENDING, "worker-1")
    with pytest.raises(InvalidSessionTransition, match="expired or mismatched"):
        coordinator.accept_termination_receipt(wrong_owner, receipt, store=store, verifier=OnlyForTestsVerifier())


def test_cleanup_requires_separate_termination_and_cleanup_evidence(setup_supervisor, now):
    coordinator, pending, command, store, _ = setup_supervisor
    coordinator.accept_acknowledgement(
        pending,
        WorkerCommandAcknowledgement(command.command_id, command.session_id, command.worker_id, True, now),
        store=store,
        verifier=OnlyForTestsVerifier(),
    )
    receipt = TerminationReceipt("session-1", "worker-1", command.command_id, True, now)
    terminated = coordinator.accept_termination_receipt(
        pending, receipt, store=store, verifier=OnlyForTestsVerifier()
    )
    cleanup_pending = coordinator.begin_cleanup(terminated, store=store)
    assert cleanup_pending.state is SessionState.CLEANUP_PENDING
    cleanup_receipt = CleanupReceipt(
        "session-1", "worker-1", True, now,
        operation_id=command.command_id,
        runtime_terminated=True,
        temporary_storage_removed=True,
        session_data_removed=True,
        credentials_disposed=True,
        temporary_artifacts_removed=True,
    )
    cleaned = coordinator.verify_cleanup(
        cleanup_pending, cleanup_receipt, verifier=OnlyForTestsCleanupVerifier(), store=store
    )
    assert cleaned.state is SessionState.CLEANUP_VERIFIED


def test_verified_acknowledgement_is_recorded_without_termination_claim(setup_supervisor, now):
    coordinator, pending, command, store, _ = setup_supervisor
    acknowledgement = WorkerCommandAcknowledgement(
        command.command_id, command.session_id, command.worker_id, True, now
    )
    coordinator.accept_acknowledgement(
        pending, acknowledgement, store=store, verifier=OnlyForTestsVerifier()
    )
    assert store.has_acknowledgement(command.command_id)
    assert pending.state is SessionState.TERMINATION_PENDING
    with pytest.raises(InvalidSessionTransition, match="already recorded"):
        coordinator.accept_acknowledgement(
            pending, acknowledgement, store=store, verifier=OnlyForTestsVerifier()
        )


def test_unverified_acknowledgement_is_not_recorded(setup_supervisor, now):
    coordinator, pending, command, store, _ = setup_supervisor
    acknowledgement = WorkerCommandAcknowledgement(
        command.command_id, command.session_id, command.worker_id, True, now
    )
    with pytest.raises(InvalidSessionTransition, match="could not be verified"):
        coordinator.accept_acknowledgement(
            pending, acknowledgement, store=store, verifier=OnlyForTestsVerifier(accepted=False)
        )
    assert not store.has_acknowledgement(command.command_id)


def test_cleanup_failure_is_explicit_and_can_only_retry_from_failure():
    pending = BrowserSession("session-1", "alice", SessionState.CLEANUP_PENDING, "worker-1")
    store = OnlyForTestsOperationStore()
    store.session_states[pending.session_id] = pending
    failed = WorkerSupervisorCoordinator.record_cleanup_failure(pending, store=store)
    assert failed.state is SessionState.CLEANUP_FAILED
    retried = WorkerSupervisorCoordinator.retry_cleanup(failed, store=store)
    assert retried.state is SessionState.CLEANUP_PENDING
    with pytest.raises(InvalidSessionTransition):
        WorkerSupervisorCoordinator.retry_cleanup(pending, store=store)


def test_uncertain_termination_can_be_quarantined_without_claiming_success(setup_supervisor):
    coordinator, pending, _, _, _ = setup_supervisor
    quarantined = coordinator.quarantine_uncertain_termination(pending)
    assert quarantined.state is SessionState.QUARANTINED
    assert quarantined.state is not SessionState.TERMINATED
