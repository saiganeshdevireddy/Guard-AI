"""Authenticated policy and lifecycle endpoints for browser-session requests.

These endpoints record authorization metadata only. There is no worker client,
VM provisioning, browser display, or cleanup verifier in this application.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.agents.controller import controller_ai
from app.database import BrowserSessionRecord, get_db
from app.security.auth import require_permission
from app.services.worker_communication import DatabaseWorkerRegistry
from app.services.browser_session_manager import (
    BrowserPrincipal,
    BrowserSession,
    BrowserSessionPolicy,
    CleanupEvidenceVerifier,
    InvalidSessionTransition,
    SessionState,
    WorkerRegistry,
    WorkerSupervisor,
    transition_session,
)

router = APIRouter(prefix="/sandbox/sessions", tags=["Browser Sessions"])

# The freshness window is an application policy constant. It does not make a
# worker trusted; registrations must still come from a trusted verified source.
browser_session_policy = BrowserSessionPolicy(health_max_age=timedelta(seconds=30))


class CreateBrowserSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explicit_user_authorization: StrictBool


def get_defence_policy_enabled() -> bool:
    """Read policy from Defence AI's server-owned state, never from the request."""
    return controller_ai.defence.browser_session_policy_enabled()


def get_worker_id(db: Session = Depends(get_db)) -> str | None:
    """Select only a currently registered worker with validated fresh health evidence."""
    return DatabaseWorkerRegistry(db).get_available_worker_id()


def get_worker_registry(db: Session = Depends(get_db)) -> WorkerRegistry:
    """Use the database-backed verified evidence adapter; absence remains UNKNOWN."""
    return DatabaseWorkerRegistry(db)


def get_worker_supervisor() -> WorkerSupervisor | None:
    """No worker supervisor is implemented or configured."""
    return None


def get_cleanup_verifier() -> CleanupEvidenceVerifier | None:
    """No cleanup evidence verifier is implemented or configured."""
    return None


def _api_error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
    )


def _session_payload(record: BrowserSessionRecord) -> dict:
    return {
        "session_id": record.session_id,
        "state": record.state,
        "policy_version": record.policy_version,
        "runtime_started": False,
        "runtime_status": "NOT_IMPLEMENTED",
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "authorized_at": record.authorized_at.isoformat() if record.authorized_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }


def _get_owned_record(db: Session, session_id: str, owner_id: str) -> BrowserSessionRecord:
    try:
        record = db.query(BrowserSessionRecord).filter_by(
            session_id=session_id,
            owner_id=owner_id,
        ).one_or_none()
    except SQLAlchemyError:
        raise _api_error(503, "session_store_unavailable", "Browser session data is unavailable.") from None
    if record is None:
        # Do not reveal whether another user's session ID exists.
        raise _api_error(404, "session_not_found", "Browser session was not found.")
    return record


def _domain_session(record: BrowserSessionRecord) -> BrowserSession:
    return BrowserSession(
        session_id=record.session_id,
        owner_id=record.owner_id,
        state=SessionState(record.state),
        worker_id=record.worker_id,
        policy_version=record.policy_version,
    )


def _authorization_response(record: BrowserSessionRecord) -> dict:
    return _session_payload(record)


@router.post("", status_code=status.HTTP_201_CREATED)
def authorize_browser_session(
    request: CreateBrowserSessionRequest,
    idempotency_key: str = Header(
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9._~-]+$",
        alias="Idempotency-Key",
    ),
    user: dict = Depends(require_permission("sandbox:write")),
    db: Session = Depends(get_db),
    defence_policy_enabled: bool = Depends(get_defence_policy_enabled),
    worker_id: str | None = Depends(get_worker_id),
    worker_registry: WorkerRegistry | None = Depends(get_worker_registry),
):
    """Record an authorized request only; this endpoint never provisions a browser."""
    if request.explicit_user_authorization is not True:
        raise _api_error(403, "explicit_authorization_required", "Explicit user authorization is required.")

    principal = BrowserPrincipal.from_authenticated_user(user)
    owner_id = principal.subject
    if not owner_id:
        raise _api_error(403, "session_not_authorized", "This account cannot authorize browser sessions.")

    key_hash = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    try:
        existing = db.query(BrowserSessionRecord).filter_by(
            owner_id=owner_id,
            idempotency_key_hash=key_hash,
        ).one_or_none()
    except SQLAlchemyError:
        raise _api_error(503, "session_store_unavailable", "Browser session data is unavailable.") from None
    if existing is not None:
        return _authorization_response(existing)

    if type(defence_policy_enabled) is not bool:
        raise _api_error(503, "browser_session_policy_unavailable", "Browser session authorization is unavailable.")

    # Defence's product policy is a separate gate from the deterministic
    # lifecycle policy below. A controller or caller cannot set either result.
    defence_worker_authorized = False
    if defence_policy_enabled is True and worker_id and worker_registry is not None:
        try:
            registration = worker_registry.get_registration(worker_id)
            defence_worker_authorized = controller_ai.defence.authorizes_browser_worker(
                registration,
                now=datetime.now(timezone.utc),
                max_age=browser_session_policy.health_max_age,
            )
        except Exception:
            defence_worker_authorized = False

    decision = browser_session_policy.evaluate_launch(
        principal=principal,
        owner_id=owner_id,
        explicit_user_authorization=request.explicit_user_authorization,
        defence_policy_enabled=defence_policy_enabled and defence_worker_authorized,
        worker_id=worker_id or "",
        worker_registry=worker_registry,
    )
    if not decision.allowed:
        # Keep internal policy reasons, worker identifiers, and health details private.
        if "not authorized" in decision.reason or "identity is required" in decision.reason:
            raise _api_error(403, "session_not_authorized", "This account cannot authorize browser sessions.")
        raise _api_error(503, "browser_session_unavailable", "Browser session authorization is unavailable.")

    session_id = secrets.token_urlsafe(24)
    try:
        authorized = transition_session(
            BrowserSession(session_id=session_id, owner_id=owner_id),
            SessionState.AUTHORIZED,
            decision=decision,
        )
    except InvalidSessionTransition:
        raise _api_error(503, "browser_session_unavailable", "Browser session authorization is unavailable.") from None

    record = BrowserSessionRecord(
        session_id=authorized.session_id,
        owner_id=authorized.owner_id,
        idempotency_key_hash=key_hash,
        state=authorized.state.value,
        worker_id=authorized.worker_id,
        policy_version=authorized.policy_version or BrowserSessionPolicy.POLICY_VERSION,
        authorized_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
    except IntegrityError:
        db.rollback()
        # A concurrent retry with the same owner's key returns the existing record.
        try:
            existing = db.query(BrowserSessionRecord).filter_by(
                owner_id=owner_id,
                idempotency_key_hash=key_hash,
            ).one_or_none()
        except SQLAlchemyError:
            raise _api_error(503, "session_store_unavailable", "Browser session data is unavailable.") from None
        if existing is not None:
            return _authorization_response(existing)
        raise _api_error(503, "session_store_unavailable", "Browser session data is unavailable.") from None
    except SQLAlchemyError:
        db.rollback()
        raise _api_error(503, "session_store_unavailable", "Browser session data is unavailable.") from None

    return _authorization_response(record)


@router.get("/{session_id}")
def get_browser_session(
    session_id: str = Path(min_length=24, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    user: dict = Depends(require_permission("sandbox:write")),
    db: Session = Depends(get_db),
):
    principal = BrowserPrincipal.from_authenticated_user(user)
    record = _get_owned_record(db, session_id, principal.subject)
    return _session_payload(record)


@router.post("/{session_id}/provision")
def provision_browser_session(
    session_id: str = Path(min_length=24, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    user: dict = Depends(require_permission("sandbox:write")),
    db: Session = Depends(get_db),
    supervisor: WorkerSupervisor | None = Depends(get_worker_supervisor),
):
    """Provisioning remains unavailable until a real supervisor can attest its operation."""
    principal = BrowserPrincipal.from_authenticated_user(user)
    record = _get_owned_record(db, session_id, principal.subject)
    if record.state != SessionState.AUTHORIZED.value:
        raise _api_error(409, "invalid_session_transition", "This browser session cannot be provisioned from its current state.")
    if supervisor is None:
        raise _api_error(503, "browser_runtime_unavailable", "Browser runtime provisioning is unavailable.")
    # Even a configured client cannot bypass the lifecycle's accepted-evidence gate.
    try:
        transition_session(_domain_session(record), SessionState.PROVISIONING)
    except InvalidSessionTransition:
        raise _api_error(503, "browser_runtime_unavailable", "Browser runtime provisioning is unavailable.") from None
    raise _api_error(503, "browser_runtime_unavailable", "Browser runtime provisioning is unavailable.")


@router.post("/{session_id}/close")
def close_browser_session(
    session_id: str = Path(min_length=24, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    user: dict = Depends(require_permission("sandbox:write")),
    db: Session = Depends(get_db),
    cleanup_verifier: CleanupEvidenceVerifier | None = Depends(get_cleanup_verifier),
):
    """Closure requires authenticated cleanup evidence; the verifier is currently absent."""
    principal = BrowserPrincipal.from_authenticated_user(user)
    record = _get_owned_record(db, session_id, principal.subject)
    if record.state != SessionState.CLEANUP_PENDING.value:
        raise _api_error(409, "invalid_session_transition", "This browser session cannot be closed from its current state.")
    if cleanup_verifier is None:
        raise _api_error(503, "cleanup_unverified", "Browser session cleanup has not been verified.")
    try:
        transition_session(
            _domain_session(record),
            SessionState.CLOSED,
            cleanup_verifier=cleanup_verifier,
        )
    except InvalidSessionTransition:
        raise _api_error(503, "cleanup_unverified", "Browser session cleanup has not been verified.") from None
    raise _api_error(503, "cleanup_unverified", "Browser session cleanup has not been verified.")
