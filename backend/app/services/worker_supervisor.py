"""Worker-independent orchestration for a future authenticated worker adapter.

No network channel or persistent operation store is configured by the application.
This coordinator therefore cannot be used to claim that a worker was contacted or
that a runtime stopped. Production use requires durable, atomic storage plus an
authenticated transport and independently verified worker receipts.
"""
import base64
import json
import re
import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Protocol
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

from app.services.browser_session_manager import (
    BrowserPrincipal,
    BrowserSession,
    CleanupEvidenceVerifier,
    CleanupReceipt,
    InvalidSessionTransition,
    SessionState,
    TerminationEvidenceVerifier,
    TerminationReceipt,
    WorkerHealth,
    WorkerRegistration,
    WorkerRegistry,
    transition_session,
)
from app.database import SessionLocal
from app.services.worker_communication import WorkerCommunicationService, WorkerSecurityError


@dataclass(frozen=True)
class TerminationCommand:
    command_id: str
    session_id: str
    worker_id: str
    owner_id: str
    issued_at: datetime
    expires_at: datetime
    signing_key_id: str = ""
    signature_b64url: str = ""

    def signed_bytes(self) -> bytes:
        payload = {
            "command_id": self.command_id,
            "command_type": "TERMINATE_SESSION",
            "session_id": self.session_id,
            "worker_id": self.worker_id,
            "owner_id": self.owner_id,
            "issued_at": self.issued_at.astimezone(timezone.utc).isoformat(),
            "expires_at": self.expires_at.astimezone(timezone.utc).isoformat(),
            "signing_key_id": self.signing_key_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class WorkerCommandSigner(Protocol):
    def sign(self, command: TerminationCommand) -> TerminationCommand: ...


class AsymmetricWorkerCommandSigner:
    """Sign commands with an operator-supplied asymmetric private key."""

    def __init__(self, private_key_pem: str, key_id: str):
        self.key_id = key_id
        self._key = None
        if (not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", key_id)
                or not isinstance(private_key_pem, str) or not private_key_pem):
            return
        try:
            self._key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        except (ValueError, TypeError, UnicodeError):
            self._key = None

    @classmethod
    def from_settings(cls):
        from app.config import settings
        return cls(settings.WORKER_COMMAND_SIGNING_KEY_PEM, settings.WORKER_COMMAND_SIGNING_KEY_ID)

    @property
    def configured(self) -> bool:
        return self._key is not None

    def sign(self, command: TerminationCommand) -> TerminationCommand:
        if self._key is None:
            raise RuntimeError("worker command signing is not configured")
        unsigned = replace(command, signing_key_id=self.key_id, signature_b64url="")
        message = unsigned.signed_bytes()
        if isinstance(self._key, rsa.RSAPrivateKey):
            signature = self._key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(self._key, ec.EllipticCurvePrivateKey):
            signature = self._key.sign(message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(self._key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            signature = self._key.sign(message)
        else:
            raise RuntimeError("worker command signing key type is unsupported")
        return replace(unsigned, signature_b64url=base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"))


class ConfiguredWorkerCommandVerifier:
    """Verify persisted commands against the configured signing key.

    The public key is derived from the operator-configured private key. This
    deliberately fails closed when the key is absent or invalid.
    """

    def __init__(self, private_key_pem: str, key_id: str):
        self._key_id = key_id
        self._public_key = None
        try:
            key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
            self._public_key = key.public_key()
        except (AttributeError, ValueError, TypeError, UnicodeError):
            self._public_key = None

    @classmethod
    def from_settings(cls):
        from app.config import settings
        return cls(settings.WORKER_COMMAND_SIGNING_KEY_PEM, settings.WORKER_COMMAND_SIGNING_KEY_ID)

    def verify(self, command: TerminationCommand, *, now: datetime) -> bool:
        if (self._public_key is None or command.signing_key_id != self._key_id
                or not command.signature_b64url):
            return False
        return verify_signed_worker_command(
            command,
            {self._key_id: self._public_key},
            expected_worker_id=command.worker_id,
            now=now,
        )


def verify_signed_worker_command(
    command: TerminationCommand,
    trusted_public_keys: dict[str, object],
    *,
    expected_worker_id: str,
    now: datetime | None = None,
    max_ttl: timedelta = timedelta(seconds=30),
) -> bool:
    """Worker-side signature, identity and expiry check using trusted public keys."""
    key = trusted_public_keys.get(command.signing_key_id)
    if key is None or not command.signature_b64url:
        return False
    try:
        current = now or datetime.now(timezone.utc)
        if (current.tzinfo is None or command.issued_at.tzinfo is None or command.expires_at.tzinfo is None
                or command.worker_id != expected_worker_id
                or not command.command_id or not command.session_id or not command.owner_id
                or command.expires_at <= current or command.issued_at > current
                or command.expires_at - command.issued_at > max_ttl
                or command.expires_at <= command.issued_at):
            return False
        encoded = command.signature_b64url.encode("ascii")
        signature = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        unsigned = replace(command, signature_b64url="")
        message = unsigned.signed_bytes()
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(signature, message)
        else:
            return False
        return True
    except Exception:
        return False


@dataclass(frozen=True)
class WorkerCommandAcknowledgement:
    command_id: str
    session_id: str
    worker_id: str
    accepted: bool
    observed_at: datetime
    signature_b64url: str = ""

    def signed_bytes(self) -> bytes:
        payload = {
            "command_id": self.command_id,
            "session_id": self.session_id,
            "worker_id": self.worker_id,
            "accepted": self.accepted,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class WorkerAcknowledgementVerifier(Protocol):
    def verify_acknowledgement(
        self, acknowledgement: WorkerCommandAcknowledgement, command: TerminationCommand
    ) -> bool: ...


class SupervisorOperationStore(Protocol):
    """Durable implementation must atomically persist and consume command IDs.

    ``put`` must enforce at most one unexpired termination command per session.
    """

    def put(
        self, command: TerminationCommand, expected: BrowserSession, pending: BrowserSession
    ) -> None: ...
    def get(self, command_id: str) -> TerminationCommand | None: ...
    def begin_delivery_attempt(self, command_id: str, now: datetime) -> bool: ...
    def mark_delivered(self, command_id: str, now: datetime) -> bool: ...
    def begin_delivery_attempt(self, command_id: str, now: datetime) -> bool: ...
    def mark_delivered(self, command_id: str, now: datetime) -> bool: ...
    def record_acknowledgement(
        self, command_id: str, acknowledgement: WorkerCommandAcknowledgement
    ) -> bool: ...
    def has_acknowledgement(self, command_id: str) -> bool: ...
    def consume_result(
        self, command_id: str, expected: BrowserSession, terminated: BrowserSession,
        receipt: TerminationReceipt,
    ) -> bool: ...
    def begin_cleanup(self, expected: BrowserSession, pending: BrowserSession) -> bool: ...
    def commit_cleanup(
        self, expected: BrowserSession, cleaned: BrowserSession, receipt: CleanupReceipt
    ) -> bool: ...
    def record_cleanup_failure(self, expected: BrowserSession, failed: BrowserSession) -> bool: ...
    def retry_cleanup(self, expected: BrowserSession, pending: BrowserSession) -> bool: ...


class WorkerCommandTransport(Protocol):
    """Authenticated, least-privilege command channel; no implementation is configured."""

    def authenticate_worker(self, expected_worker_id: str) -> str | None:
        """Return the worker identity proven by the channel or None on failure."""

    def deliver_termination(self, command: TerminationCommand) -> None:
        """Deliver command; return means delivery only, never termination."""


class DatabaseWorkerMessageVerifier:
    """Verify worker receipts with the enrolled, currently trusted certificate."""

    def __init__(self, *, session_factory=SessionLocal, worker_service=None):
        self._session_factory = session_factory
        self._worker_service = worker_service or WorkerCommunicationService()

    def _verify(self, worker_id: str, message: bytes, signature: str) -> bool:
        db = self._session_factory()
        try:
            return self._worker_service.verify_worker_signed_message(
                db, worker_id=worker_id, message=message, signature_b64url=signature,
            ) is True
        except WorkerSecurityError:
            return False
        finally:
            db.close()

    def verify_acknowledgement(
        self, acknowledgement: WorkerCommandAcknowledgement, command: TerminationCommand
    ) -> bool:
        return (
            acknowledgement.command_id == command.command_id
            and acknowledgement.session_id == command.session_id
            and acknowledgement.worker_id == command.worker_id
            and acknowledgement.accepted is True
            and self._verify(command.worker_id, acknowledgement.signed_bytes(), acknowledgement.signature_b64url)
        )

    def verify_termination_receipt(self, receipt: TerminationReceipt, session: BrowserSession) -> bool:
        return (
            receipt.session_id == session.session_id
            and receipt.worker_id == session.worker_id
            and receipt.terminated is True
            and self._verify(receipt.worker_id, receipt.signed_bytes(), receipt.signature_b64url)
        )



class WorkerSupervisorCoordinator:
    COMMAND_TTL = timedelta(seconds=30)

    def __init__(
        self, *, clock, signer: WorkerCommandSigner | None = None,
        registration_max_age: timedelta = timedelta(seconds=30),
    ):
        self._clock = clock
        self._signer = signer
        self._registration_max_age = registration_max_age

    def request_termination(
        self,
        session: BrowserSession,
        *,
        principal: BrowserPrincipal,
        registry: WorkerRegistry,
        store: SupervisorOperationStore,
        transport: WorkerCommandTransport,
    ) -> tuple[BrowserSession, TerminationCommand]:
        """Authorize and dispatch a bounded request; session remains pending."""
        if (principal.subject != session.owner_id
                or ("*" not in principal.permissions and "sandbox:write" not in principal.permissions)):
            raise PermissionError("session owner authorization is required")
        if session.state not in {
            SessionState.ACTIVE, SessionState.STOPPING, SessionState.TERMINATION_PENDING
        } or not session.worker_id:
            raise InvalidSessionTransition("termination requires an active assigned worker session")
        try:
            now = self._clock()
            registration = registry.get_registration(session.worker_id)
        except Exception:
            raise RuntimeError("worker registry is unavailable") from None
        if (not isinstance(now, datetime) or now.tzinfo is None
                or not isinstance(registration, WorkerRegistration)
                or registration.worker_id != session.worker_id
                or registration.health not in {WorkerHealth.HEALTHY, WorkerHealth.UNHEALTHY}
                or not registration.evidence_verified
                or registration.observed_at is None or registration.observed_at.tzinfo is None
                or not timedelta(0) <= now - registration.observed_at <= self._registration_max_age):
            raise RuntimeError("registered worker identity or freshness is unverified")
        command = TerminationCommand(
            command_id=secrets.token_urlsafe(24),
            session_id=session.session_id,
            worker_id=session.worker_id,
            owner_id=principal.subject,
            issued_at=now,
            expires_at=now + self.COMMAND_TTL,
        )
        if self._signer is None:
            raise RuntimeError("worker command signing is not configured")
        unsigned_command = command
        try:
            command = self._signer.sign(command)
        except Exception:
            raise RuntimeError("worker command signing failed") from None
        if (not command.signing_key_id or not command.signature_b64url
                or command.command_id != unsigned_command.command_id
                or command.session_id != unsigned_command.session_id
                or command.worker_id != unsigned_command.worker_id
                or command.owner_id != unsigned_command.owner_id
                or command.issued_at != unsigned_command.issued_at
                or command.expires_at != unsigned_command.expires_at):
            raise RuntimeError("signed worker command is malformed")
        stopping = (
            transition_session(session, SessionState.CANCEL_REQUESTED)
            if session.state is SessionState.ACTIVE
            else session
        )
        pending = (
            stopping if stopping.state is SessionState.TERMINATION_PENDING
            else transition_session(stopping, SessionState.TERMINATION_PENDING)
        )
        # The store must compare-and-set and persist this transition with command
        # creation, preventing duplicate requests from stale session snapshots.
        store.put(command, session, pending)
        # Persist cancellation intent before attempting the channel. Authentication
        # or delivery failure leaves a recoverable pending operation; nothing is
        # reported as terminated and the command is never sent on an untrusted link.
        try:
            authenticated_worker = transport.authenticate_worker(session.worker_id)
        except Exception:
            raise RuntimeError("worker channel authentication failed") from None
        if authenticated_worker != session.worker_id:
            raise RuntimeError("worker channel identity does not match the assigned worker")
        delivery_at = self._clock()
        if (not isinstance(delivery_at, datetime) or delivery_at.tzinfo is None
                or delivery_at >= command.expires_at):
            raise RuntimeError("worker command expired before delivery")
        if not store.begin_delivery_attempt(command.command_id, delivery_at):
            raise RuntimeError("worker command delivery attempt could not be persisted")
        transport.deliver_termination(command)
        if not store.mark_delivered(command.command_id, self._clock()):
            raise RuntimeError("worker command delivery result could not be persisted")
        return pending, command

    def accept_termination_receipt(
        self,
        session: BrowserSession,
        receipt: TerminationReceipt,
        *,
        store: SupervisorOperationStore,
        verifier: TerminationEvidenceVerifier,
    ) -> BrowserSession:
        """Consume one result and advance only after independent verification."""
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise InvalidSessionTransition("trusted supervisor clock is unavailable")
        command = store.get(receipt.operation_id)
        if (not isinstance(receipt.observed_at, datetime) or receipt.observed_at.tzinfo is None
                or command is not None and (
                    not isinstance(command.issued_at, datetime) or command.issued_at.tzinfo is None
                    or not isinstance(command.expires_at, datetime) or command.expires_at.tzinfo is None
                )):
            raise InvalidSessionTransition("termination receipt timestamp is invalid")
        if (command is None or command.session_id != session.session_id
                or command.worker_id != session.worker_id or command.owner_id != session.owner_id
                or command.command_id != receipt.operation_id
                or command.issued_at > receipt.observed_at or receipt.observed_at > now
                or command.expires_at <= now or receipt.terminated is not True
                or receipt.session_id != command.session_id or receipt.worker_id != command.worker_id):
            raise InvalidSessionTransition("termination receipt is expired or mismatched")
        if not store.has_acknowledgement(command.command_id):
            raise InvalidSessionTransition("worker command acknowledgement is missing")
        try:
            verified = verifier.verify_termination_receipt(receipt, session)
        except Exception:
            verified = False
        if verified is not True:
            raise InvalidSessionTransition("worker termination evidence could not be verified")
        terminated = transition_session(
            session,
            SessionState.TERMINATED,
            termination_receipt=receipt,
            termination_verifier=verifier,
        )
        # A production store must persist TERMINATED and consume this result in
        # one transaction. The receipt is never enough to mutate state by itself.
        if not store.consume_result(command.command_id, session, terminated, receipt):
            raise InvalidSessionTransition("termination receipt was already consumed")
        return terminated

    def accept_acknowledgement(
        self,
        session: BrowserSession,
        acknowledgement: WorkerCommandAcknowledgement,
        *,
        store: SupervisorOperationStore,
        verifier: WorkerAcknowledgementVerifier,
    ) -> None:
        """Record a verified worker response without claiming VM termination."""
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise InvalidSessionTransition("trusted supervisor clock is unavailable")
        command = store.get(acknowledgement.command_id)
        if (command is None or not isinstance(acknowledgement.observed_at, datetime)
                or acknowledgement.observed_at.tzinfo is None
                or command.issued_at > acknowledgement.observed_at
                or acknowledgement.observed_at > now or command.expires_at <= now
                or command.session_id != session.session_id or command.owner_id != session.owner_id
                or command.worker_id != session.worker_id
                or acknowledgement.command_id != command.command_id
                or acknowledgement.session_id != command.session_id
                or acknowledgement.worker_id != command.worker_id
                or acknowledgement.accepted is not True
                or session.state is not SessionState.TERMINATION_PENDING):
            raise InvalidSessionTransition("worker acknowledgement is expired or mismatched")
        try:
            verified = verifier.verify_acknowledgement(acknowledgement, command)
        except Exception:
            verified = False
        if verified is not True:
            raise InvalidSessionTransition("worker acknowledgement could not be verified")
        if not store.record_acknowledgement(command.command_id, acknowledgement):
            raise InvalidSessionTransition("worker acknowledgement was already recorded")

    @staticmethod
    def begin_cleanup(session: BrowserSession, *, store: SupervisorOperationStore) -> BrowserSession:
        pending = transition_session(session, SessionState.CLEANUP_PENDING)
        if not store.begin_cleanup(session, pending):
            raise InvalidSessionTransition("cleanup operation could not be persisted")
        return pending

    @staticmethod
    def verify_cleanup(
        session: BrowserSession,
        receipt: CleanupReceipt,
        *,
        verifier: CleanupEvidenceVerifier,
        store: SupervisorOperationStore,
    ) -> BrowserSession:
        cleaned = transition_session(
            session,
            SessionState.CLEANUP_VERIFIED,
            cleanup_receipt=receipt,
            cleanup_verifier=verifier,
        )
        if not store.commit_cleanup(session, cleaned, receipt):
            raise InvalidSessionTransition("cleanup evidence could not be persisted")
        return cleaned

    @staticmethod
    def record_cleanup_failure(
        session: BrowserSession, *, store: SupervisorOperationStore
    ) -> BrowserSession:
        """Retain an explicit failure state so cleanup can be retried or escalated."""
        failed = transition_session(session, SessionState.CLEANUP_FAILED)
        if not store.record_cleanup_failure(session, failed):
            raise InvalidSessionTransition("cleanup failure state could not be persisted")
        return failed

    @staticmethod
    def retry_cleanup(session: BrowserSession, *, store: SupervisorOperationStore) -> BrowserSession:
        pending = transition_session(session, SessionState.CLEANUP_PENDING)
        if not store.retry_cleanup(session, pending):
            raise InvalidSessionTransition("cleanup retry could not be persisted")
        return pending

    @staticmethod
    def quarantine_uncertain_termination(session: BrowserSession) -> BrowserSession:
        """Quarantine uncertain state; this does not assert the runtime stopped."""
        return transition_session(session, SessionState.QUARANTINED)
