from datetime import datetime, timedelta, timezone

import pytest

from app.services.browser_session_manager import (
    BrowserPrincipal,
    BrowserSession,
    BrowserSessionPolicy,
    CleanupReceipt,
    InvalidSessionTransition,
    PolicyDecision,
    SessionState,
    TerminationReceipt,
    WorkerHealth,
    WorkerRegistration,
    transition_session,
)


class StubWorkerRegistry:
    def __init__(self, registration=None, *, error=False):
        self.registration = registration
        self.error = error

    def get_registration(self, worker_id):
        if self.error:
            raise RuntimeError("registry unavailable")
        return self.registration


@pytest.fixture
def policy(now):
    return BrowserSessionPolicy(health_max_age=timedelta(seconds=30), clock=lambda: now)


@pytest.fixture
def now():
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def operator():
    return BrowserPrincipal("alice", frozenset({"sandbox:write"}))


def healthy_worker(now):
    return WorkerRegistration("worker-a", WorkerHealth.HEALTHY, now - timedelta(seconds=1), True)


def decide(policy, now, operator, worker=None, **overrides):
    args = {
        "principal": operator,
        "owner_id": "alice",
        "explicit_user_authorization": True,
        "defence_policy_enabled": True,
        "worker_id": "worker-a",
        "worker_registry": StubWorkerRegistry(worker),
    }
    args.update(overrides)
    return policy.evaluate_launch(**args)


def test_policy_allows_explicit_owner_with_fresh_registered_healthy_worker(policy, now, operator):
    decision = decide(policy, now, operator, healthy_worker(now))
    assert decision.allowed is True
    assert decision.worker_id == "worker-a"


@pytest.mark.parametrize(
    ("worker", "overrides", "reason"),
    [
        (None, {}, "no registered worker"),
        (WorkerRegistration("worker-a", evidence_verified=True), {}, "health is not confirmed"),
        (WorkerRegistration("worker-a", WorkerHealth.UNHEALTHY, datetime(2026, 1, 1, tzinfo=timezone.utc), True), {}, "health is not confirmed"),
        (WorkerRegistration("worker-a", WorkerHealth.HEALTHY, datetime(2026, 1, 1, tzinfo=timezone.utc)), {}, "not verified"),
        (WorkerRegistration("worker-a", WorkerHealth.HEALTHY, datetime(2025, 1, 1, tzinfo=timezone.utc), True), {}, "stale"),
        (WorkerRegistration("worker-a", WorkerHealth.HEALTHY, datetime(2026, 1, 2, tzinfo=timezone.utc), True), {}, "timestamp is invalid"),
        (WorkerRegistration("worker-a", WorkerHealth.HEALTHY, datetime(2025, 12, 31), True), {}, "timestamp is invalid"),
        (WorkerRegistration("different-worker", WorkerHealth.HEALTHY, datetime(2026, 1, 1, tzinfo=timezone.utc), True), {}, "identity"),
        (None, {"explicit_user_authorization": False}, "explicit user authorization"),
        (None, {"owner_id": "bob"}, "owner does not match"),
        (None, {"principal": BrowserPrincipal("alice", frozenset())}, "not authorized"),
        (None, {"defence_policy_enabled": False}, "Defence browser policy"),
    ],
)
def test_policy_denies_missing_or_invalid_prerequisites(policy, now, operator, worker, overrides, reason):
    decision = decide(policy, now, operator, worker, **overrides)
    assert decision.allowed is False
    assert reason in decision.reason


def test_policy_denies_registry_failure(policy, now, operator):
    decision = policy.evaluate_launch(
        principal=operator,
        owner_id="alice",
        explicit_user_authorization=True,
        defence_policy_enabled=True,
        worker_id="worker-a",
        worker_registry=StubWorkerRegistry(error=True),
    )
    assert decision.allowed is False
    assert "registry is unavailable" in decision.reason


def test_policy_denies_when_worker_registry_is_not_configured(policy, now, operator):
    decision = policy.evaluate_launch(
        principal=operator,
        owner_id="alice",
        explicit_user_authorization=True,
        defence_policy_enabled=True,
        worker_id="worker-a",
        worker_registry=None,
    )
    assert decision.allowed is False


def test_controller_agent_permission_cannot_substitute_for_browser_user_permission(policy, now):
    controller = BrowserPrincipal("controller", frozenset({"agents:write"}))
    decision = decide(
        policy,
        now,
        controller,
        healthy_worker(now),
        owner_id="controller",
    )
    assert decision.allowed is False
    assert "not authorized" in decision.reason


def test_callers_cannot_override_trusted_policy_clock(policy, now, operator):
    with pytest.raises(TypeError):
        policy.evaluate_launch(
            principal=operator,
            owner_id="alice",
            explicit_user_authorization=True,
            defence_policy_enabled=True,
            worker_id="worker-a",
            worker_registry=StubWorkerRegistry(healthy_worker(now)),
            now=now - timedelta(days=1),
        )


def test_unavailable_trusted_clock_denies_launch(now, operator):
    policy_with_bad_clock = BrowserSessionPolicy(
        health_max_age=timedelta(seconds=30),
        clock=lambda: None,
    )
    decision = decide(policy_with_bad_clock, now, operator, healthy_worker(now))
    assert decision.allowed is False
    assert "timestamp is invalid" in decision.reason


def test_authorization_decision_is_bound_to_session_owner():
    session = BrowserSession("session-a", "bob")
    decision = PolicyDecision(True, "authorized", "policy-v1", "worker-a", "alice")
    with pytest.raises(InvalidSessionTransition, match="affirmative policy decision"):
        transition_session(session, SessionState.AUTHORIZED, decision=decision)


def test_authorized_transition_requires_positive_policy_decision():
    session = BrowserSession("session-a", "alice")
    allowed = PolicyDecision(True, "authorized", "policy-v1", "worker-a", "alice")
    denied = PolicyDecision(False, "no worker", "policy-v1")

    authorized = transition_session(session, SessionState.AUTHORIZED, decision=allowed)
    assert authorized.state is SessionState.AUTHORIZED
    assert authorized.owner_id == "alice"
    assert authorized.worker_id == "worker-a"
    with pytest.raises(InvalidSessionTransition):
        transition_session(session, SessionState.AUTHORIZED, decision=denied)
    with pytest.raises(InvalidSessionTransition):
        transition_session(session, SessionState.AUTHORIZED)


def test_authorized_session_can_be_cancelled_and_cancellation_is_terminal():
    authorized = BrowserSession("session-a", "alice", SessionState.AUTHORIZED, "worker-a", "policy-v1")
    cancelled = transition_session(authorized, SessionState.CANCELLED)
    assert cancelled.state is SessionState.CANCELLED
    with pytest.raises(InvalidSessionTransition):
        transition_session(cancelled, SessionState.AUTHORIZED)


def test_denial_is_terminal_and_requires_negative_policy_decision():
    session = BrowserSession("session-a", "alice")
    denied = transition_session(
        session,
        SessionState.DENIED,
        decision=PolicyDecision(False, "worker unavailable", "policy-v1"),
    )
    assert denied.state is SessionState.DENIED
    with pytest.raises(InvalidSessionTransition):
        transition_session(denied, SessionState.AUTHORIZED, decision=PolicyDecision(True, "ok", "v1", "w", "alice"))
    with pytest.raises(InvalidSessionTransition):
        transition_session(session, SessionState.DENIED, decision=PolicyDecision(True, "ok", "v1", "w", "alice"))


def test_provisioning_and_active_require_future_supervisor_evidence():
    session = BrowserSession("session-a", "alice", SessionState.AUTHORIZED, "worker-a", "policy-v1")
    with pytest.raises(InvalidSessionTransition, match="accepted supervisor operation"):
        transition_session(session, SessionState.PROVISIONING)
    provisioning = BrowserSession("session-a", "alice", SessionState.PROVISIONING, "worker-a", "policy-v1")
    with pytest.raises(InvalidSessionTransition, match="authenticated worker attestation"):
        transition_session(provisioning, SessionState.ACTIVE)


def test_cleanup_pending_cannot_be_closed_without_matching_verified_receipt():
    cleanup_pending = BrowserSession("session-a", "alice", SessionState.CLEANUP_PENDING, "worker-a")
    with pytest.raises(InvalidSessionTransition, match="verified cleanup evidence"):
        transition_session(cleanup_pending, SessionState.CLOSED)
    with pytest.raises(InvalidSessionTransition, match="verified cleanup evidence"):
        transition_session(
            cleanup_pending,
            SessionState.CLOSED,
            cleanup_receipt=CleanupReceipt("session-other", "worker-a", True, datetime.now(timezone.utc)),
        )


def test_cleanup_receipt_cannot_close_session_without_verifier():
    cleanup_pending = BrowserSession("session-a", "alice", SessionState.CLEANUP_PENDING, "worker-a")
    receipt = CleanupReceipt(
        "session-a", "worker-a", True, datetime.now(timezone.utc),
        runtime_terminated=True, temporary_storage_removed=True,
        session_data_removed=True, credentials_disposed=True, temporary_artifacts_removed=True,
    )
    with pytest.raises(InvalidSessionTransition, match="verified cleanup evidence"):
        transition_session(cleanup_pending, SessionState.CLOSED, cleanup_receipt=receipt)


def test_cleanup_verifier_failure_keeps_session_unclosed():
    class RejectingVerifier:
        def verify_cleanup_receipt(self, receipt, session):
            return False

    cleanup_pending = BrowserSession("session-a", "alice", SessionState.CLEANUP_PENDING, "worker-a")
    receipt = CleanupReceipt(
        "session-a", "worker-a", True, datetime.now(timezone.utc),
        runtime_terminated=True, temporary_storage_removed=True,
        session_data_removed=True, credentials_disposed=True, temporary_artifacts_removed=True,
    )
    with pytest.raises(InvalidSessionTransition, match="could not be verified"):
        transition_session(
            cleanup_pending,
            SessionState.CLOSED,
            cleanup_receipt=receipt,
            cleanup_verifier=RejectingVerifier(),
        )
    assert cleanup_pending.state is SessionState.CLEANUP_PENDING


def test_cleanup_failure_can_be_quarantined_and_retried():
    cleanup_pending = BrowserSession("session-a", "alice", SessionState.CLEANUP_PENDING, "worker-a")
    quarantined = transition_session(cleanup_pending, SessionState.QUARANTINED)
    assert quarantined.state is SessionState.QUARANTINED
    retried = transition_session(quarantined, SessionState.CLEANUP_PENDING)
    assert retried.state is SessionState.CLEANUP_PENDING


def test_runtime_termination_state_requires_bound_independent_evidence(now):
    pending = BrowserSession("session-a", "alice", SessionState.TERMINATION_PENDING, "worker-a")
    with pytest.raises(InvalidSessionTransition, match="verified worker evidence"):
        transition_session(pending, SessionState.TERMINATED)

    class AcceptingVerifier:
        def verify_termination_receipt(self, receipt, session):
            return receipt.operation_id == "op-1" and session.session_id == receipt.session_id

    receipt = TerminationReceipt("session-a", "worker-a", "op-1", True, now)
    terminated = transition_session(
        pending,
        SessionState.TERMINATED,
        termination_receipt=receipt,
        termination_verifier=AcceptingVerifier(),
    )
    assert terminated.state is SessionState.TERMINATED


def test_cleanup_verified_state_requires_separate_cleanup_verification(now):
    pending = BrowserSession("session-a", "alice", SessionState.CLEANUP_PENDING, "worker-a")
    receipt = CleanupReceipt("session-a", "worker-a", True, now)
    with pytest.raises(InvalidSessionTransition, match="verified cleanup evidence"):
        transition_session(pending, SessionState.CLEANUP_VERIFIED, cleanup_receipt=receipt)


def test_unknown_worker_health_cannot_authorize_transition():
    session = BrowserSession("session-a", "alice")
    decision = PolicyDecision(False, "worker health is not confirmed healthy", "policy-v1")
    denied = transition_session(session, SessionState.DENIED, decision=decision)
    assert denied.state is SessionState.DENIED
