"""Worker-independent browser-session policy and lifecycle primitives.

This module does not start a browser or provision a VM. It defines the local
control-plane contract that a future authenticated Worker Supervisor adapter
must satisfy. Until that adapter exists, no real session can become active.
"""
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Protocol


class WorkerHealth(str, Enum):
    UNKNOWN = "UNKNOWN"
    UNHEALTHY = "UNHEALTHY"
    HEALTHY = "HEALTHY"


@dataclass(frozen=True)
class WorkerRegistration:
    """Control-plane view of a registered worker; only trusted registries may assert evidence verification."""

    worker_id: str
    health: WorkerHealth = WorkerHealth.UNKNOWN
    observed_at: datetime | None = None
    evidence_verified: bool = False


class WorkerRegistry(Protocol):
    """Read-only registration/health interface for an independently monitored worker."""

    def get_registration(self, worker_id: str) -> WorkerRegistration | None:
        """Return None when the worker is not registered."""


class WorkerSupervisor(Protocol):
    """Transport contract for a separately authenticated worker supervisor.

    The current application does not configure an implementation. Implementations
    must treat command delivery as pending until a verifier accepts worker evidence.
    """

    def request_start(self, session_id: str, owner_id: str, policy_version: str) -> str:
        """Request a session-scoped start and return its worker operation ID."""

    def request_stop(self, session_id: str, worker_id: str) -> str:
        """Request stop; completion must be checked separately."""

    def verify_cleanup(self, session_id: str, worker_id: str) -> "CleanupReceipt | None":
        """Return a cleanup report for a separate trusted verifier, or None if uncertain."""


class CleanupEvidenceVerifier(Protocol):
    """Trust-boundary interface; no verifier is implemented or configured yet."""

    def verify_cleanup_receipt(self, receipt: "CleanupReceipt", session: "BrowserSession") -> bool:
        """Verify provenance, session/worker binding, and resource absence evidence."""


class TerminationEvidenceVerifier(Protocol):
    """Independently verify that a worker attests the targeted runtime is terminated."""

    def verify_termination_receipt(self, receipt: "TerminationReceipt", session: "BrowserSession") -> bool:
        """Verify authenticated provenance and session/worker/operation binding."""


@dataclass(frozen=True)
class BrowserPrincipal:
    """Identity and permissions derived from an authenticated API principal."""

    subject: str
    permissions: frozenset[str]

    @classmethod
    def from_authenticated_user(cls, user: dict) -> "BrowserPrincipal":
        """Adapt the existing auth dependency result; agent identities are not users."""
        from app.security.auth import ROLE_PERMISSIONS

        subject = user.get("username")
        role = user.get("role")
        if not isinstance(subject, str) or not subject or role not in ROLE_PERMISSIONS:
            return cls(subject="", permissions=frozenset())
        return cls(subject=subject, permissions=frozenset(ROLE_PERMISSIONS[role]))


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    policy_version: str
    worker_id: str | None = None
    subject: str | None = None


class BrowserSessionPolicy:
    """Deterministic independent authorization gate; Controller is not an input."""

    POLICY_VERSION = "browser-session-policy-v1"

    def __init__(
        self,
        *,
        health_max_age: timedelta,
        clock: Callable[[], datetime] | None = None,
    ):
        if health_max_age <= timedelta(0):
            raise ValueError("health_max_age must be positive")
        self.health_max_age = health_max_age
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def evaluate_launch(
        self,
        *,
        principal: BrowserPrincipal | None,
        owner_id: str,
        explicit_user_authorization: bool,
        defence_policy_enabled: bool,
        worker_id: str,
        worker_registry: WorkerRegistry | None,
    ) -> PolicyDecision:
        if principal is None or not principal.subject:
            return self._deny("authenticated user identity is required")
        if principal.subject != owner_id:
            return self._deny("session owner does not match authenticated user")
        if "*" not in principal.permissions and "sandbox:write" not in principal.permissions:
            return self._deny("user is not authorized to create browser sessions")
        if explicit_user_authorization is not True:
            return self._deny("explicit user authorization is required")
        if defence_policy_enabled is not True:
            return self._deny("Defence browser policy is disabled or unavailable")
        if not worker_id or worker_registry is None:
            return self._deny("worker registry or worker identity is unavailable")
        try:
            worker = worker_registry.get_registration(worker_id)
        except Exception:
            return self._deny("worker registry is unavailable")
        if worker is None:
            return self._deny("no registered worker is available")
        if not isinstance(worker, WorkerRegistration):
            return self._deny("worker registration has an invalid type")
        if worker.evidence_verified is not True:
            return self._deny("worker health evidence is not verified")
        if worker.health is not WorkerHealth.HEALTHY:
            return self._deny("worker health is not confirmed healthy")
        if worker.worker_id != worker_id or not isinstance(worker.observed_at, datetime):
            return self._deny("worker registration lacks identity or health evidence")
        try:
            now = self._clock()
        except Exception:
            return self._deny("trusted clock is unavailable")
        if not isinstance(now, datetime) or now.tzinfo is None or worker.observed_at.tzinfo is None or worker.observed_at > now:
            return self._deny("worker health timestamp is invalid")
        try:
            health_age = now - worker.observed_at
        except (TypeError, OverflowError):
            return self._deny("worker health timestamp is invalid")
        if health_age > self.health_max_age:
            return self._deny("worker health evidence is stale")
        return PolicyDecision(
            True,
            "launch authorized by user and Defence policy",
            self.POLICY_VERSION,
            worker.worker_id,
            principal.subject,
        )

    def _deny(self, reason: str) -> PolicyDecision:
        return PolicyDecision(False, reason, self.POLICY_VERSION)


class SessionState(str, Enum):
    REQUESTED = "REQUESTED"
    AUTHORIZED = "AUTHORIZED"
    CANCELLED = "CANCELLED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    STOPPING = "STOPPING"
    TERMINATION_PENDING = "TERMINATION_PENDING"
    TERMINATED = "TERMINATED"
    CLEANUP_PENDING = "CLEANUP_PENDING"
    CLEANUP_VERIFIED = "CLEANUP_VERIFIED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    CLOSED = "CLOSED"
    DENIED = "DENIED"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True)
class BrowserSession:
    """Metadata-only lifecycle record; deliberately contains no URL or page data."""

    session_id: str
    owner_id: str
    state: SessionState = SessionState.REQUESTED
    worker_id: str | None = None
    policy_version: str | None = None


@dataclass(frozen=True)
class CleanupReceipt:
    """Receipt shape required from a future authenticated cleanup verifier.

    Constructing this value does not itself prove cleanup. Only a trusted
    supervisor adapter may supply it; the adapter is not implemented here.
    """

    session_id: str
    worker_id: str
    resources_absent: bool
    verified_at: datetime
    signature_b64url: str = ""
    operation_id: str = ""
    runtime_terminated: bool = False
    temporary_storage_removed: bool = False
    session_data_removed: bool = False
    credentials_disposed: bool = False
    temporary_artifacts_removed: bool = False

    def signed_bytes(self) -> bytes:
        payload = {
            "session_id": self.session_id,
            "worker_id": self.worker_id,
            "operation_id": self.operation_id,
            "resources_absent": self.resources_absent,
            "runtime_terminated": self.runtime_terminated,
            "temporary_storage_removed": self.temporary_storage_removed,
            "session_data_removed": self.session_data_removed,
            "credentials_disposed": self.credentials_disposed,
            "temporary_artifacts_removed": self.temporary_artifacts_removed,
            "verified_at": self.verified_at.astimezone(timezone.utc).isoformat(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class TerminationReceipt:
    """Untrusted worker claim; it becomes evidence only after verifier acceptance."""

    session_id: str
    worker_id: str
    operation_id: str
    terminated: bool
    observed_at: datetime
    signature_b64url: str = ""

    def signed_bytes(self) -> bytes:
        payload = {
            "session_id": self.session_id,
            "worker_id": self.worker_id,
            "operation_id": self.operation_id,
            "terminated": self.terminated,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class InvalidSessionTransition(ValueError):
    pass


_ALLOWED_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.REQUESTED: frozenset({SessionState.AUTHORIZED, SessionState.DENIED}),
    SessionState.AUTHORIZED: frozenset({SessionState.PROVISIONING, SessionState.DENIED, SessionState.CANCELLED}),
    SessionState.CANCELLED: frozenset(),
    SessionState.CANCEL_REQUESTED: frozenset({SessionState.TERMINATION_PENDING, SessionState.QUARANTINED}),
    SessionState.PROVISIONING: frozenset({SessionState.ACTIVE, SessionState.CLEANUP_PENDING, SessionState.QUARANTINED}),
    SessionState.ACTIVE: frozenset({SessionState.STOPPING, SessionState.CANCEL_REQUESTED, SessionState.QUARANTINED}),
    SessionState.STOPPING: frozenset({SessionState.TERMINATION_PENDING, SessionState.QUARANTINED}),
    SessionState.TERMINATION_PENDING: frozenset({SessionState.TERMINATED, SessionState.QUARANTINED}),
    SessionState.TERMINATED: frozenset({SessionState.CLEANUP_PENDING}),
    SessionState.CLEANUP_PENDING: frozenset({SessionState.CLOSED, SessionState.CLEANUP_VERIFIED, SessionState.CLEANUP_FAILED, SessionState.QUARANTINED}),
    SessionState.CLEANUP_FAILED: frozenset({SessionState.CLEANUP_PENDING, SessionState.QUARANTINED}),
    SessionState.CLEANUP_VERIFIED: frozenset(),
    SessionState.QUARANTINED: frozenset({SessionState.CLEANUP_PENDING, SessionState.CLEANUP_FAILED}),
    SessionState.CLOSED: frozenset(),
    SessionState.DENIED: frozenset(),
}


def transition_session(
    session: BrowserSession,
    target: SessionState,
    *,
    decision: PolicyDecision | None = None,
    cleanup_receipt: CleanupReceipt | None = None,
    cleanup_verifier: CleanupEvidenceVerifier | None = None,
    termination_receipt: TerminationReceipt | None = None,
    termination_verifier: TerminationEvidenceVerifier | None = None,
) -> BrowserSession:
    """Apply an allowed state transition and enforce authorization/cleanup gates."""
    if target not in _ALLOWED_TRANSITIONS[session.state]:
        raise InvalidSessionTransition(f"cannot transition {session.state.value} to {target.value}")
    if target is SessionState.AUTHORIZED and (
        decision is None or not decision.allowed or not decision.worker_id
        or decision.subject != session.owner_id
    ):
        raise InvalidSessionTransition("authorization requires an affirmative policy decision")
    if target is SessionState.DENIED and (decision is None or decision.allowed):
        raise InvalidSessionTransition("denial requires a negative policy decision")
    if target is SessionState.TERMINATED:
        if (termination_receipt is None or termination_receipt.session_id != session.session_id
                or termination_receipt.worker_id != session.worker_id
                or not termination_receipt.operation_id
                or termination_receipt.terminated is not True
                or termination_receipt.observed_at.tzinfo is None
                or termination_verifier is None):
            raise InvalidSessionTransition("terminated requires matching verified worker evidence")
        try:
            verified_termination = termination_verifier.verify_termination_receipt(termination_receipt, session)
        except Exception:
            verified_termination = False
        if verified_termination is not True:
            raise InvalidSessionTransition("worker termination evidence could not be verified")
    if target in {SessionState.CLOSED, SessionState.CLEANUP_VERIFIED}:
        if (cleanup_receipt is None or cleanup_receipt.session_id != session.session_id
                or cleanup_receipt.worker_id != session.worker_id
                or cleanup_receipt.resources_absent is not True
                or cleanup_receipt.runtime_terminated is not True
                or cleanup_receipt.temporary_storage_removed is not True
                or cleanup_receipt.session_data_removed is not True
                or cleanup_receipt.credentials_disposed is not True
                or cleanup_receipt.temporary_artifacts_removed is not True
                or cleanup_receipt.verified_at.tzinfo is None
                or cleanup_verifier is None):
            raise InvalidSessionTransition("closed requires matching verified cleanup evidence")
        try:
            verified = cleanup_verifier.verify_cleanup_receipt(cleanup_receipt, session)
        except Exception:
            verified = False
        if verified is not True:
            raise InvalidSessionTransition("cleanup evidence could not be verified")
    if target is SessionState.ACTIVE:
        raise InvalidSessionTransition("active requires a future authenticated worker attestation")
    if target is SessionState.PROVISIONING:
        raise InvalidSessionTransition("provisioning requires a future accepted supervisor operation")
    policy_version = decision.policy_version if target is SessionState.AUTHORIZED and decision else session.policy_version
    worker_id = decision.worker_id if target is SessionState.AUTHORIZED and decision else session.worker_id
    return replace(session, state=target, policy_version=policy_version, worker_id=worker_id)
