"""Administrative worker enrollment and fail-closed mTLS worker channels."""
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.security.auth import require_permission
from app.services.worker_communication import (
    WorkerCommunicationService,
    WorkerHealthEvidence,
    WorkerSecurityError,
    certificate_from_asgi_scope,
)

router = APIRouter(prefix="/workers", tags=["Worker Communication"])
internal_router = APIRouter(prefix="/internal/workers", tags=["Worker Communication"])


class WorkerRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    certificate_pem: str = Field(min_length=64, max_length=16384)
    intermediate_pems: list[str] = Field(default_factory=list, max_length=8)


class WorkerHealthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    worker_id: str = Field(min_length=1, max_length=128)
    status: str = Field(pattern=r"^(HEALTHY|UNHEALTHY)$")
    observed_at: datetime
    sequence: int = Field(ge=1)
    nonce: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    signature_b64url: str = Field(min_length=32, max_length=1024)


class TicketRedemptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ticket: str = Field(min_length=32, max_length=4096)


class TicketDeliveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=24, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


def _raise_worker_error(error: WorkerSecurityError):
    # Avoid returning certificate details, ticket claims, SQL errors, or signatures.
    message = str(error)
    if ("already registered" in message or "replayed" in message or "conflicted" in message
            or "already used" in message or "already exists" in message or "consumed" in message):
        code, status_code = "worker_conflict", status.HTTP_409_CONFLICT
    elif ("not registered" in message or "not authorized" in message or "revoked" in message
          or "mismatch" in message):
        code, status_code = "worker_not_authorized", status.HTTP_403_FORBIDDEN
    elif "certificate" in message or "mutual TLS" in message or "trusted" in message:
        code, status_code = "worker_authentication_failed", status.HTTP_401_UNAUTHORIZED
    elif "expired" in message or "invalid" in message or "malformed" in message:
        code, status_code = "worker_evidence_rejected", status.HTTP_400_BAD_REQUEST
    else:
        code, status_code = "worker_service_unavailable", status.HTTP_503_SERVICE_UNAVAILABLE
    raise HTTPException(status_code, detail={"code": code, "message": "Worker security validation failed."}) from None


@router.post("/{worker_id}/register", status_code=status.HTTP_201_CREATED)
def register_worker(
    body: WorkerRegistrationRequest,
    worker_id: str = Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    user: dict = Depends(require_permission("workers:write")),
    db: Session = Depends(get_db),
):
    """Enrollment is administrative and accepts only a CA-trusted client certificate."""
    try:
        record = WorkerCommunicationService().register_worker(
            db,
            worker_id=worker_id,
            certificate_pem=body.certificate_pem,
            intermediate_pems=body.intermediate_pems,
            actor=user["username"],
        )
        return {
            "worker_id": record.worker_id,
            "certificate_sha256": record.certificate_fingerprint,
            "status": record.status,
            "certificate_expires_at": record.certificate_expires_at.isoformat(),
        }
    except WorkerSecurityError as error:
        _raise_worker_error(error)


@router.post("/{worker_id}/revoke")
def revoke_worker(
    worker_id: str = Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    user: dict = Depends(require_permission("workers:write")),
    db: Session = Depends(get_db),
):
    try:
        revoked = WorkerCommunicationService().revoke_worker(db, worker_id=worker_id, actor=user["username"])
        return {"worker_id": worker_id, "status": "REVOKED" if revoked else "ALREADY_REVOKED"}
    except WorkerSecurityError as error:
        _raise_worker_error(error)


@router.put("/{worker_id}/certificate")
def renew_worker_certificate(
    body: WorkerRegistrationRequest,
    worker_id: str = Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    user: dict = Depends(require_permission("workers:write")),
    db: Session = Depends(get_db),
):
    """Replace a worker's certificate through an audited admin-only renewal operation."""
    try:
        record = WorkerCommunicationService().renew_worker_certificate(
            db,
            worker_id=worker_id,
            certificate_pem=body.certificate_pem,
            intermediate_pems=body.intermediate_pems,
            actor=user["username"],
        )
        return {
            "worker_id": record.worker_id,
            "certificate_sha256": record.certificate_fingerprint,
            "status": record.status,
            "certificate_expires_at": record.certificate_expires_at.isoformat(),
        }
    except WorkerSecurityError as error:
        _raise_worker_error(error)


@router.post("/tickets/{ticket_id}/revoke")
def revoke_ticket(
    ticket_id: str = Path(min_length=16, max_length=64),
    user: dict = Depends(require_permission("workers:write")),
    db: Session = Depends(get_db),
):
    try:
        revoked = WorkerCommunicationService().revoke_ticket(
            db, ticket_id=ticket_id, actor=user["username"]
        )
        if not revoked:
            raise HTTPException(404, detail={"code": "ticket_not_found", "message": "Worker ticket was not found."})
        return {"ticket_id": ticket_id, "status": "REVOKED"}
    except WorkerSecurityError as error:
        _raise_worker_error(error)


@internal_router.post("/{worker_id}/sessions/{session_id}/redeem")
def redeem_worker_ticket(
    request: Request,
    body: TicketRedemptionRequest,
    worker_id: str = Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    session_id: str = Path(min_length=24, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    db: Session = Depends(get_db),
):
    service = WorkerCommunicationService()
    try:
        peer_der = certificate_from_asgi_scope(request.scope)
        worker = service.authenticate_peer_certificate(db, peer_der)
        if worker.worker_id != worker_id:
            raise WorkerSecurityError("worker identity mismatch")
        service.redeem_session_ticket(
            db, token=body.ticket, peer_worker_id=worker_id, expected_session_id=session_id
        )
        # This confirms only one-time authorization redemption, never VM startup.
        return {"authorized": True, "session_id": session_id, "runtime_started": False}
    except WorkerSecurityError as error:
        _raise_worker_error(error)


@internal_router.post("/{worker_id}/sessions/{session_id}/ticket")
def deliver_worker_ticket(
    request: Request,
    response: Response,
    body: TicketDeliveryRequest,
    delivery_id: str = Header(
        min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._~-]+$", alias="Delivery-Id"
    ),
    worker_id: str = Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    session_id: str = Path(min_length=24, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    db: Session = Depends(get_db),
):
    """Deliver the same short-lived ticket on retries, only over authenticated mTLS."""
    service = WorkerCommunicationService()
    try:
        worker = service.authenticate_peer_certificate(db, certificate_from_asgi_scope(request.scope))
        if worker.worker_id != worker_id or body.session_id != session_id:
            raise WorkerSecurityError("worker or session identity mismatch")
        from app.database import BrowserSessionRecord
        session = db.query(BrowserSessionRecord).filter_by(session_id=session_id).one_or_none()
        if session is None:
            raise WorkerSecurityError("session is not authorized for this worker")
        ticket_id, ticket, expires_at = service.issue_session_ticket(
            db,
            session_id=session_id,
            subject_id=session.owner_id,
            worker_id=worker_id,
            delivery_id=delivery_id,
        )
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
        # Response bodies are never logged by this application; deployment access
        # logs must omit response bodies and the Delivery-Id header.
        return {"ticket_id": ticket_id, "ticket": ticket, "expires_at": expires_at.isoformat()}
    except WorkerSecurityError as error:
        _raise_worker_error(error)


@internal_router.post("/health")
def report_worker_health(
    request: Request,
    body: WorkerHealthRequest,
    db: Session = Depends(get_db),
):
    service = WorkerCommunicationService()
    try:
        worker = service.authenticate_peer_certificate(db, certificate_from_asgi_scope(request.scope))
        evidence = WorkerHealthEvidence(
            worker_id=body.worker_id,
            status=body.status,
            observed_at=body.observed_at,
            sequence=body.sequence,
            nonce=body.nonce,
            signature_b64url=body.signature_b64url,
        )
        health = service.accept_health_evidence(db, peer_worker=worker, evidence=evidence)
        return {"worker_id": health.worker_id, "status": health.status, "observed_at": health.observed_at.isoformat()}
    except WorkerSecurityError as error:
        _raise_worker_error(error)
