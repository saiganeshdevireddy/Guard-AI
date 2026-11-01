"""Fail-closed worker identity, ticket, mTLS certificate, and health evidence primitives.

No network client, worker process, VM lifecycle, or provisioning adapter is created here.
The ASGI application accepts worker identity only from a TLS extension supplied by a
TLS-capable ASGI server; ordinary HTTP headers are never treated as certificate proof.
"""
import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509 import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import settings
from app.core.audit_chain import AuditChainService
from app.database import (
    BrowserSessionRecord,
    WorkerAuthorizationTicketRecord,
    WorkerHealthRecord,
    WorkerIdentityRecord,
    WorkerSigningKeyState,
)
from app.services.browser_session_manager import WorkerHealth, WorkerRegistration, WorkerRegistry


class WorkerSecurityError(ValueError):
    """A fail-closed worker security validation error safe to map to a generic response."""


@dataclass(frozen=True)
class WorkerHealthEvidence:
    worker_id: str
    status: str
    observed_at: datetime
    sequence: int
    nonce: str
    signature_b64url: str

    def signed_bytes(self) -> bytes:
        payload = {
            "worker_id": self.worker_id,
            "status": self.status,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
            "sequence": self.sequence,
            "nonce": self.nonce,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_certificates(pem_bundle: str) -> list[x509.Certificate]:
    if not isinstance(pem_bundle, str) or len(pem_bundle) > 65536:
        raise WorkerSecurityError("certificate configuration is invalid")
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_bundle, re.DOTALL
    )
    if not blocks:
        raise WorkerSecurityError("certificate configuration is invalid")
    try:
        return [x509.load_pem_x509_certificate(block.encode("ascii")) for block in blocks]
    except (ValueError, UnicodeError):
        raise WorkerSecurityError("certificate configuration is invalid") from None


def _verify_client_certificate(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    ca_pem: str,
    crl_pem: str,
    now: datetime,
) -> None:
    roots = _load_certificates(ca_pem)
    try:
        verifier = PolicyBuilder().store(Store(roots)).time(now).build_client_verifier()
        verifier.verify(leaf, intermediates)
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            raise WorkerSecurityError("certificate is not valid for client authentication")
        _verify_certificate_revocation([leaf, *intermediates], roots, crl_pem, now)
    except WorkerSecurityError:
        raise
    except Exception:
        raise WorkerSecurityError("worker certificate is untrusted or outside its validity period") from None


def _verify_certificate_revocation(
    chain: list[x509.Certificate], roots: list[x509.Certificate], crl_pem: str, now: datetime
) -> None:
    """Require fresh issuer-signed CRLs for all non-root certificates."""
    if not isinstance(crl_pem, str) or not crl_pem or len(crl_pem) > 65536:
        raise WorkerSecurityError("trusted certificate revocation list is unavailable")
    blocks = re.findall(
        r"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----", crl_pem, re.DOTALL
    )
    try:
        crls = [x509.load_pem_x509_crl(block.encode("ascii")) for block in blocks]
    except (ValueError, UnicodeError):
        raise WorkerSecurityError("certificate revocation list is invalid") from None
    issuers = [*chain[1:], *roots]
    for certificate in chain:
        issuer = next((item for item in issuers if item.subject == certificate.issuer), None)
        if issuer is None:
            raise WorkerSecurityError("certificate issuer is unavailable for revocation checking")
        valid_crl = None
        for crl in (item for item in crls if item.issuer == issuer.subject):
            if crl.last_update_utc > now or crl.next_update_utc is None or crl.next_update_utc <= now:
                continue
            try:
                public_key = issuer.public_key()
                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(crl.signature, crl.tbs_certlist_bytes, padding.PKCS1v15(), crl.signature_hash_algorithm)
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(crl.signature_hash_algorithm))
                elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                    public_key.verify(crl.signature, crl.tbs_certlist_bytes)
                else:
                    continue
                valid_crl = crl
                break
            except Exception:
                continue
        if valid_crl is None:
            raise WorkerSecurityError("fresh trusted certificate revocation list is unavailable")
        if valid_crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None:
            raise WorkerSecurityError("worker certificate is revoked by its issuing authority")


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def _check_registered_certificate(
    record: WorkerIdentityRecord,
    ca_pem: str,
    crl_pem: str,
    now: datetime,
) -> x509.Certificate:
    if record.status != "ACTIVE":
        raise WorkerSecurityError("worker identity is revoked")
    try:
        bundle = _load_certificates(record.certificate_chain_pem)
        leaf = x509.load_pem_x509_certificate(record.certificate_pem.encode("ascii"))
        expiration = record.certificate_expires_at
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        if expiration <= now or certificate_fingerprint(leaf) != record.certificate_fingerprint:
            raise WorkerSecurityError("worker certificate is expired or mismatched")
        if not bundle or certificate_fingerprint(bundle[0]) != record.certificate_fingerprint:
            raise WorkerSecurityError("worker certificate chain is mismatched")
        _verify_client_certificate(leaf, bundle[1:], ca_pem, crl_pem, now)
        return leaf
    except WorkerSecurityError:
        raise
    except Exception:
        raise WorkerSecurityError("worker certificate is invalid") from None


class WorkerCommunicationService:
    TICKET_ISSUER = "guard-ai-worker-authorization"
    TICKET_AUDIENCE = "guard-ai-worker"
    SESSION_AUTH_MAX_AGE = timedelta(minutes=5)
    HEALTH_MAX_AGE = timedelta(seconds=30)

    def __init__(
        self, *, ca_pem: str | None = None, crl_pem: str | None = None, ticket_secret: str | None = None,
        ticket_key_id: str | None = None, previous_ticket_keys: dict[str, str] | None = None,
        clock=None,
    ):
        self.ca_pem = settings.WORKER_CA_CERT_PEM if ca_pem is None else ca_pem
        self.crl_pem = settings.WORKER_CRL_PEM if crl_pem is None else crl_pem
        self.ticket_secret = settings.WORKER_TICKET_SIGNING_KEY if ticket_secret is None else ticket_secret
        self.ticket_key_id = settings.WORKER_TICKET_SIGNING_KEY_ID if ticket_key_id is None else ticket_key_id
        active_key_id_valid = isinstance(self.ticket_key_id, str)
        self.ticket_keys = ({self.ticket_key_id: self.ticket_secret}
                            if active_key_id_valid and self.ticket_secret else {})
        try:
            configured_previous = (json.loads(settings.WORKER_TICKET_VERIFY_KEYS_JSON)
                                   if previous_ticket_keys is None else previous_ticket_keys)
            if not isinstance(configured_previous, dict):
                configured_previous = None
            if configured_previous is not None:
                self.ticket_keys.update(configured_previous)
        except (TypeError, json.JSONDecodeError):
            configured_previous = None
        self.ticket_configuration_valid = bool(
            active_key_id_valid
            and re.fullmatch(r"[A-Za-z0-9._-]{1,32}", self.ticket_key_id or "")
            and isinstance(self.ticket_secret, str) and len(self.ticket_secret) >= 32
            and configured_previous is not None
            and all(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,32}", key)
                    and isinstance(value, str) and len(value) >= 32
                    for key, value in self.ticket_keys.items())
            and self.ticket_keys.get(self.ticket_key_id) == self.ticket_secret
        )
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _record_required_audit(
        db: Session, *, actor: str, event_type: str, payload: dict,
    ) -> None:
        """Persist an audit event or fail the protected operation closed."""
        try:
            AuditChainService.record_event(db, actor=actor, event_type=event_type, payload=payload)
        except Exception:
            db.rollback()
            raise WorkerSecurityError("worker security audit is unavailable") from None

    @staticmethod
    def _begin_authorization_transaction(db: Session) -> None:
        """Serialize ticket authorization with health/session changes where supported.

        PostgreSQL row locks are taken by the reauthorization reads. SQLite's
        default driver does not begin a database transaction on SELECT, so take
        an immediate write reservation before reading authorization state.
        """
        connection = db.connection()
        if connection.dialect.name == "sqlite":
            raw_connection = connection.connection.driver_connection
            if not raw_connection.in_transaction:
                connection.exec_driver_sql("BEGIN IMMEDIATE")

    def _reauthorize_session_worker(
        self, db: Session, *, session_id: str, subject_id: str, worker_id: str, now: datetime,
    ) -> tuple[BrowserSessionRecord, WorkerIdentityRecord]:
        """Recheck Defence and signed worker health inside the ticket transaction."""
        try:
            session = db.query(BrowserSessionRecord).filter_by(session_id=session_id).with_for_update().one_or_none()
            identity = db.query(WorkerIdentityRecord).filter_by(worker_id=worker_id).with_for_update().one_or_none()
            health_record = db.query(WorkerHealthRecord).filter_by(worker_id=worker_id).with_for_update().one_or_none()
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker authorization storage is unavailable") from None

        is_session_authorized = (
            session is not None
            and session.owner_id == subject_id
            and session.worker_id == worker_id
            and session.state == "AUTHORIZED"
            and session.authorized_at is not None
            and now >= _as_utc(session.authorized_at)
            and now - _as_utc(session.authorized_at) <= self.SESSION_AUTH_MAX_AGE
        )
        if not is_session_authorized or identity is None or identity.status != "ACTIVE":
            raise WorkerSecurityError("worker session authorization is no longer valid")
        if health_record is None:
            raise WorkerSecurityError("current signed worker health is unavailable")
        _check_registered_certificate(identity, self.ca_pem, self.crl_pem, now)

        # The registry re-verifies the persisted payload/signature against the
        # currently enrolled certificate. A fresh status column by itself is
        # never accepted as health evidence.
        registration = DatabaseWorkerRegistry(db, self).get_registration(worker_id)
        if (registration is None or registration.worker_id != worker_id
                or registration.health is not WorkerHealth.HEALTHY
                or registration.evidence_verified is not True
                or registration.observed_at is None
                or registration.observed_at.tzinfo is None
                or now.tzinfo is None
                or not timedelta(0) <= now - registration.observed_at <= self.HEALTH_MAX_AGE):
            raise WorkerSecurityError("current signed worker health is unavailable or unhealthy")

        # Defence is the server-owned policy gate. Controller orchestration and
        # ticket claims cannot replace it.
        from app.agents.controller import controller_ai
        if controller_ai.defence.authorizes_browser_worker(
            registration, now=now, max_age=self.HEALTH_MAX_AGE,
        ) is not True:
            raise WorkerSecurityError("Defence policy denies worker authorization")
        return session, identity

    def record_key_configuration(self, db: Session, *, actor: str = "Guard AI Worker Key Manager") -> bool:
        """Audit active key-ID changes without persisting or logging any key material."""
        if not self.ticket_configuration_valid:
            return False
        try:
            state = db.query(WorkerSigningKeyState).filter_by(id=1).one_or_none()
            if state is not None and state.active_key_id == self.ticket_key_id:
                return False
            prior_id = state.active_key_id if state else None
            if state is None:
                db.add(WorkerSigningKeyState(id=1, active_key_id=self.ticket_key_id))
            else:
                state.active_key_id = self.ticket_key_id
                state.updated_at = self.clock()
            AuditChainService.record_event(
                db,
                actor=actor,
                event_type="WORKER_TICKET_SIGNING_KEY_CONFIGURED" if prior_id is None else "WORKER_TICKET_SIGNING_KEY_ROTATED",
                payload={"active_key_id": self.ticket_key_id, "previous_key_id": prior_id},
            )
            return True
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker key configuration audit failed") from None

    def register_worker(
        self,
        db: Session,
        *,
        worker_id: str,
        certificate_pem: str,
        intermediate_pems: list[str],
        actor: str,
    ) -> WorkerIdentityRecord:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", worker_id or ""):
            raise WorkerSecurityError("worker identity is invalid")
        if not actor or not self.ca_pem:
            raise WorkerSecurityError("worker registration is unavailable")
        if (len(certificate_pem) > 16384 or len(intermediate_pems) > 8
                or any(not isinstance(pem, str) or len(pem) > 16384 for pem in intermediate_pems)
                or sum(map(len, intermediate_pems)) > 65536):
            raise WorkerSecurityError("worker certificate input is invalid")
        try:
            leaf = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
            intermediates = [x509.load_pem_x509_certificate(pem.encode("ascii")) for pem in intermediate_pems]
            now = self.clock()
            if now.tzinfo is None:
                raise WorkerSecurityError("trusted clock is invalid")
            _verify_client_certificate(leaf, intermediates, self.ca_pem, self.crl_pem, now)
            fingerprint = certificate_fingerprint(leaf)
            if db.query(WorkerIdentityRecord).filter(
                (WorkerIdentityRecord.worker_id == worker_id)
                | (WorkerIdentityRecord.certificate_fingerprint == fingerprint)
            ).one_or_none():
                raise WorkerSecurityError("worker identity is already registered")
            chain = "\n".join([certificate_pem, *intermediate_pems])
            record = WorkerIdentityRecord(
                worker_id=worker_id,
                certificate_fingerprint=fingerprint,
                certificate_pem=certificate_pem,
                certificate_chain_pem=chain,
                certificate_expires_at=leaf.not_valid_after_utc,
                status="ACTIVE",
                registered_by=actor,
                registered_at=now,
            )
            db.add(record)
            # The existing audit service commits the identity and event in one DB transaction.
            AuditChainService.record_event(
                db,
                actor=actor,
                event_type="WORKER_IDENTITY_REGISTERED",
                payload={"worker_id": worker_id, "certificate_sha256": fingerprint},
            )
            db.refresh(record)
            return record
        except WorkerSecurityError:
            db.rollback()
            raise
        except (IntegrityError, SQLAlchemyError):
            db.rollback()
            raise WorkerSecurityError("worker registration could not be recorded") from None
        except Exception:
            db.rollback()
            raise WorkerSecurityError("worker certificate validation failed") from None

    def revoke_worker(self, db: Session, *, worker_id: str, actor: str) -> bool:
        try:
            record = db.query(WorkerIdentityRecord).filter_by(worker_id=worker_id).one_or_none()
            if record is None:
                raise WorkerSecurityError("worker identity is not registered")
            if record.status == "REVOKED":
                return False
            now = self.clock()
            record.status = "REVOKED"
            record.revoked_at = now
            db.query(WorkerAuthorizationTicketRecord).filter_by(
                worker_id=worker_id, revoked_at=None
            ).update({"revoked_at": now}, synchronize_session=False)
            AuditChainService.record_event(
                db,
                actor=actor,
                event_type="WORKER_IDENTITY_REVOKED",
                payload={"worker_id": worker_id},
            )
            return True
        except WorkerSecurityError:
            db.rollback()
            raise
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker revocation could not be recorded") from None

    def renew_worker_certificate(
        self,
        db: Session,
        *,
        worker_id: str,
        certificate_pem: str,
        intermediate_pems: list[str],
        actor: str,
    ) -> WorkerIdentityRecord:
        """Rotate an enrolled worker's public certificate; the prior fingerprint stops authenticating."""
        try:
            record = db.query(WorkerIdentityRecord).filter_by(worker_id=worker_id).one_or_none()
            if record is None or record.status != "ACTIVE":
                raise WorkerSecurityError("active worker identity is required for certificate renewal")
            if (not actor or not self.ca_pem or len(certificate_pem) > 16384
                    or len(intermediate_pems) > 8
                    or any(not isinstance(pem, str) or len(pem) > 16384 for pem in intermediate_pems)
                    or sum(map(len, intermediate_pems)) > 65536):
                raise WorkerSecurityError("worker certificate renewal is unavailable")
            leaf = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
            intermediates = [x509.load_pem_x509_certificate(pem.encode("ascii")) for pem in intermediate_pems]
            now = self.clock()
            if now.tzinfo is None:
                raise WorkerSecurityError("trusted clock is invalid")
            _verify_client_certificate(leaf, intermediates, self.ca_pem, self.crl_pem, now)
            new_fingerprint = certificate_fingerprint(leaf)
            if new_fingerprint == record.certificate_fingerprint:
                return record
            duplicate = db.query(WorkerIdentityRecord).filter(
                WorkerIdentityRecord.certificate_fingerprint == new_fingerprint,
                WorkerIdentityRecord.worker_id != worker_id,
            ).one_or_none()
            if duplicate is not None:
                raise WorkerSecurityError("worker certificate is already assigned to another identity")
            old_fingerprint = record.certificate_fingerprint
            record.certificate_fingerprint = new_fingerprint
            record.certificate_pem = certificate_pem
            record.certificate_chain_pem = "\n".join([certificate_pem, *intermediate_pems])
            record.certificate_expires_at = leaf.not_valid_after_utc
            record.registered_by = actor
            record.registered_at = now
            AuditChainService.record_event(
                db,
                actor=actor,
                event_type="WORKER_CERTIFICATE_RENEWED",
                payload={
                    "worker_id": worker_id,
                    "previous_certificate_sha256": old_fingerprint,
                    "certificate_sha256": new_fingerprint,
                },
            )
            db.refresh(record)
            return record
        except WorkerSecurityError:
            db.rollback()
            raise
        except (ValueError, UnicodeError):
            db.rollback()
            raise WorkerSecurityError("worker certificate renewal validation failed") from None
        except (IntegrityError, SQLAlchemyError):
            db.rollback()
            raise WorkerSecurityError("worker certificate renewal could not be recorded") from None
        except Exception:
            db.rollback()
            raise WorkerSecurityError("worker certificate renewal failed") from None

    def authenticate_peer_certificate(self, db: Session, certificate_der: bytes) -> WorkerIdentityRecord:
        if not isinstance(certificate_der, bytes) or not self.ca_pem:
            raise WorkerSecurityError("mutual TLS authentication is unavailable")
        try:
            cert = x509.load_der_x509_certificate(certificate_der)
            fingerprint = certificate_fingerprint(cert)
            record = db.query(WorkerIdentityRecord).filter_by(
                certificate_fingerprint=fingerprint
            ).one_or_none()
            if record is None:
                raise WorkerSecurityError("worker is not registered")
            checked = _check_registered_certificate(record, self.ca_pem, self.crl_pem, self.clock())
            if certificate_fingerprint(checked) != fingerprint:
                raise WorkerSecurityError("worker certificate identity mismatch")
            return record
        except WorkerSecurityError:
            db.rollback()
            self._record_required_audit(
                db, actor="worker-authentication", event_type="WORKER_TLS_AUTHENTICATION_REJECTED",
                payload={"reason": "certificate_validation_failed"},
            )
            raise
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker authentication storage is unavailable") from None
        except Exception:
            raise WorkerSecurityError("worker certificate authentication failed") from None

    def issue_session_ticket(
        self,
        db: Session,
        *,
        session_id: str,
        subject_id: str,
        worker_id: str,
        delivery_id: str,
        ttl: timedelta = timedelta(seconds=60),
    ) -> tuple[str, str, datetime]:
        if (not self.ticket_configuration_valid or ttl <= timedelta(0) or ttl > timedelta(minutes=5)
                or not re.fullmatch(r"[A-Za-z0-9._~-]{16,128}", delivery_id or "")):
            raise WorkerSecurityError("worker ticket issuance is unavailable")
        now = self.clock()
        if now.tzinfo is None:
            raise WorkerSecurityError("trusted clock is invalid")
        try:
            self._begin_authorization_transaction(db)
            session, _identity = self._reauthorize_session_worker(
                db, session_id=session_id, subject_id=subject_id, worker_id=worker_id, now=now,
            )
            delivery_id_hash = hashlib.sha256(delivery_id.encode()).hexdigest()
            existing = db.query(WorkerAuthorizationTicketRecord).filter_by(
                worker_id=worker_id, delivery_id_hash=delivery_id_hash
            ).with_for_update().one_or_none()
            if existing is not None:
                if (existing.session_id != session_id or existing.subject_id != subject_id
                        or existing.revoked_at is not None or existing.redeemed_at is not None
                        or _as_utc(existing.expires_at) <= now):
                    raise WorkerSecurityError("ticket delivery retry is no longer valid")
                self._record_required_audit(
                    db, actor=f"worker:{worker_id}", event_type="WORKER_TICKET_DELIVERY_RETRIED",
                    payload={"ticket_id": existing.ticket_id, "session_id": session_id, "worker_id": worker_id},
                )
                return existing.ticket_id, self._encode_ticket(existing), _as_utc(existing.expires_at)

            prior_session_ticket = db.query(WorkerAuthorizationTicketRecord).filter_by(
                session_id=session_id, worker_id=worker_id, subject_id=subject_id
            ).order_by(WorkerAuthorizationTicketRecord.created_at.desc()).with_for_update().first()
            if prior_session_ticket is not None:
                if prior_session_ticket.redeemed_at is not None or prior_session_ticket.revoked_at is not None:
                    raise WorkerSecurityError("session authorization ticket has already been consumed or revoked")
                if _as_utc(prior_session_ticket.expires_at) > now:
                    raise WorkerSecurityError("session authorization ticket already exists; retry its delivery ID")

            expires = now + ttl
            ticket_id = secrets.token_urlsafe(24)
            record = WorkerAuthorizationTicketRecord(
                ticket_id=ticket_id,
                jti_hash=hashlib.sha256(ticket_id.encode()).hexdigest(),
                delivery_id_hash=delivery_id_hash,
                key_id=self.ticket_key_id,
                session_id=session_id,
                worker_id=worker_id,
                subject_id=subject_id,
                expires_at=expires,
                created_at=now,
            )
            db.add(record)
            self._record_required_audit(
                db, actor=f"worker:{worker_id}", event_type="WORKER_AUTHORIZATION_TICKET_ISSUED",
                payload={"ticket_id": ticket_id, "session_id": session_id, "worker_id": worker_id},
            )
            return ticket_id, self._encode_ticket(record), expires
        except WorkerSecurityError:
            db.rollback()
            raise
        except IntegrityError:
            db.rollback()
            try:
                self._begin_authorization_transaction(db)
                self._reauthorize_session_worker(
                    db, session_id=session_id, subject_id=subject_id, worker_id=worker_id, now=now,
                )
                existing = db.query(WorkerAuthorizationTicketRecord).filter_by(
                    worker_id=worker_id, delivery_id_hash=delivery_id_hash
                ).with_for_update().one_or_none()
                if (existing is not None and existing.session_id == session_id
                        and existing.subject_id == subject_id and existing.revoked_at is None
                        and existing.redeemed_at is None and _as_utc(existing.expires_at) > now):
                    self._record_required_audit(
                        db, actor=f"worker:{worker_id}", event_type="WORKER_TICKET_DELIVERY_RETRIED",
                        payload={"ticket_id": existing.ticket_id, "session_id": session_id, "worker_id": worker_id},
                    )
                    return existing.ticket_id, self._encode_ticket(existing), _as_utc(existing.expires_at)
            except SQLAlchemyError:
                db.rollback()
            raise WorkerSecurityError("worker ticket could not be issued") from None
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker ticket could not be issued") from None

    def _encode_ticket(self, record: WorkerAuthorizationTicketRecord) -> str:
        created_at = _as_utc(record.created_at)
        expires_at = _as_utc(record.expires_at)
        key_id = record.key_id or self.ticket_key_id
        signing_key = self.ticket_keys.get(key_id)
        if not signing_key:
            raise WorkerSecurityError("worker ticket signing key is unavailable")
        return jwt.encode({
            "iss": self.TICKET_ISSUER,
            "aud": self.TICKET_AUDIENCE,
            "sub": record.subject_id,
            "sid": record.session_id,
            "wid": record.worker_id,
            "tid": record.ticket_id,
            "jti": record.ticket_id,
            "iat": int(created_at.timestamp()),
            "exp": int(expires_at.timestamp()),
        }, signing_key, algorithm="HS256", headers={"kid": key_id})

    def revoke_ticket(self, db: Session, *, ticket_id: str, actor: str) -> bool:
        try:
            record = db.query(WorkerAuthorizationTicketRecord).filter_by(ticket_id=ticket_id).one_or_none()
            if record is None:
                return False
            if record.revoked_at is not None:
                return False
            record.revoked_at = self.clock()
            AuditChainService.record_event(
                db,
                actor=actor,
                event_type="WORKER_AUTHORIZATION_TICKET_REVOKED",
                payload={"ticket_id": ticket_id, "worker_id": record.worker_id},
            )
            return True
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker ticket revocation could not be recorded") from None

    def redeem_session_ticket(
        self,
        db: Session,
        *,
        token: str,
        peer_worker_id: str,
        expected_session_id: str,
    ) -> dict:
        if not self.ticket_configuration_valid:
            raise WorkerSecurityError("worker ticket validation is unavailable")
        try:
            now = self.clock()
            if now.tzinfo is None:
                raise WorkerSecurityError("trusted clock is invalid")
            self._begin_authorization_transaction(db)
            key_id = jwt.get_unverified_header(token).get("kid", self.ticket_key_id)
            signing_key = self.ticket_keys.get(key_id)
            if signing_key is None:
                raise WorkerSecurityError("worker ticket signing key is unavailable")
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["HS256"],
                issuer=self.TICKET_ISSUER,
                audience=self.TICKET_AUDIENCE,
                options={"require": ["iss", "aud", "sub", "sid", "wid", "tid", "jti", "iat", "exp"]},
            )
            if claims["sid"] != expected_session_id or claims["wid"] != peer_worker_id:
                raise WorkerSecurityError("worker ticket identity mismatch")
            self._reauthorize_session_worker(
                db, session_id=claims["sid"], subject_id=claims["sub"], worker_id=peer_worker_id, now=now,
            )
            record = db.query(WorkerAuthorizationTicketRecord).filter_by(
                ticket_id=claims["tid"],
                jti_hash=hashlib.sha256(claims["jti"].encode()).hexdigest(),
                session_id=claims["sid"],
                worker_id=claims["wid"],
                subject_id=claims["sub"],
            ).with_for_update().one_or_none()
            now_naive = now.astimezone(timezone.utc).replace(tzinfo=None)
            if record is None or record.revoked_at is not None:
                raise WorkerSecurityError("worker ticket is invalid or revoked")
            if record.key_id is not None and record.key_id != key_id:
                raise WorkerSecurityError("worker ticket key identity mismatch")
            result = db.execute(
                update(WorkerAuthorizationTicketRecord)
                .where(
                    WorkerAuthorizationTicketRecord.ticket_id == record.ticket_id,
                    WorkerAuthorizationTicketRecord.redeemed_at.is_(None),
                    WorkerAuthorizationTicketRecord.revoked_at.is_(None),
                    WorkerAuthorizationTicketRecord.expires_at > now_naive,
                )
                .values(redeemed_at=now_naive)
            )
            if result.rowcount != 1:
                db.rollback()
                raise WorkerSecurityError("worker ticket is expired, revoked, or already used")
            self._record_required_audit(
                db, actor=f"worker:{peer_worker_id}", event_type="WORKER_AUTHORIZATION_TICKET_REDEEMED",
                payload={"ticket_id": record.ticket_id, "session_id": claims["sid"], "worker_id": peer_worker_id},
            )
            return {"session_id": claims["sid"], "worker_id": claims["wid"], "subject_id": claims["sub"]}
        except WorkerSecurityError:
            db.rollback()
            self._record_required_audit(
                db, actor=f"worker:{peer_worker_id}", event_type="WORKER_TICKET_REDEMPTION_REJECTED",
                payload={"session_id": expected_session_id, "worker_id": peer_worker_id,
                         "reason": "validation_failed"},
            )
            raise
        except jwt.ExpiredSignatureError:
            db.rollback()
            self._record_required_audit(
                db, actor=f"worker:{peer_worker_id}", event_type="WORKER_TICKET_REDEMPTION_REJECTED",
                payload={"session_id": expected_session_id, "worker_id": peer_worker_id,
                         "reason": "expired"},
            )
            raise WorkerSecurityError("worker ticket is expired") from None
        except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
            db.rollback()
            self._record_required_audit(
                db, actor=f"worker:{peer_worker_id}", event_type="WORKER_TICKET_REDEMPTION_REJECTED",
                payload={"session_id": expected_session_id, "worker_id": peer_worker_id,
                         "reason": "invalid"},
            )
            raise WorkerSecurityError("worker ticket is invalid") from None
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker ticket storage is unavailable") from None

    def accept_health_evidence(
        self,
        db: Session,
        *,
        peer_worker: WorkerIdentityRecord,
        evidence: WorkerHealthEvidence,
        max_age: timedelta = timedelta(seconds=30),
    ) -> WorkerHealthRecord:
        try:
            signed_bytes, payload_hash, current_peer, now = self.verify_health_evidence(
                db, peer_worker_id=peer_worker.worker_id, evidence=evidence, max_age=max_age,
                require_fresh=True,
            )
        except WorkerSecurityError:
            db.rollback()
            self._record_required_audit(
                db, actor=f"worker:{peer_worker.worker_id}",
                event_type="WORKER_HEALTH_EVIDENCE_REJECTED",
                payload={"worker_id": peer_worker.worker_id, "reason": "validation_failed"},
            )
            raise
        observed = evidence.observed_at.astimezone(timezone.utc).replace(tzinfo=None)
        try:
            existing = db.query(WorkerHealthRecord).filter_by(worker_id=peer_worker.worker_id).one_or_none()
            if existing is None:
                db.add(WorkerHealthRecord(
                    worker_id=current_peer.worker_id,
                    status=evidence.status,
                    observed_at=observed,
                    sequence=evidence.sequence,
                    evidence_hash=payload_hash,
                    evidence_payload=signed_bytes.decode("utf-8"),
                    signature_b64url=evidence.signature_b64url,
                    updated_at=now.astimezone(timezone.utc).replace(tzinfo=None),
                ))
            else:
                result = db.execute(
                    update(WorkerHealthRecord)
                    .where(
                        WorkerHealthRecord.worker_id == peer_worker.worker_id,
                        WorkerHealthRecord.sequence < evidence.sequence,
                    )
                    .values(
                        status=evidence.status,
                        observed_at=observed,
                        sequence=evidence.sequence,
                        evidence_hash=payload_hash,
                        evidence_payload=signed_bytes.decode("utf-8"),
                        signature_b64url=evidence.signature_b64url,
                        updated_at=now.astimezone(timezone.utc).replace(tzinfo=None),
                    )
                )
                if result.rowcount != 1:
                    db.rollback()
                    raise WorkerSecurityError("worker health evidence was replayed or conflicted")
            db.commit()
            return db.query(WorkerHealthRecord).filter_by(worker_id=peer_worker.worker_id).one()
        except WorkerSecurityError:
            db.rollback()
            raise
        except IntegrityError:
            db.rollback()
            raise WorkerSecurityError("worker health evidence conflicted with another update") from None
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker health storage is unavailable") from None

    def verify_health_evidence(
        self,
        db: Session,
        *,
        peer_worker_id: str,
        evidence: WorkerHealthEvidence,
        max_age: timedelta = timedelta(seconds=30),
        require_fresh: bool = True,
    ) -> tuple[bytes, str, WorkerIdentityRecord, datetime]:
        now = self.clock()
        if (evidence.worker_id != peer_worker_id or evidence.status not in {"HEALTHY", "UNHEALTHY"}
                or type(evidence.sequence) is not int or evidence.sequence < 1
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", evidence.nonce or "")
                or not isinstance(evidence.observed_at, datetime) or evidence.observed_at.tzinfo is None
                or now.tzinfo is None
                or (require_fresh and (evidence.observed_at > now or now - evidence.observed_at > max_age))):
            raise WorkerSecurityError("worker health evidence is malformed or stale")
        try:
            current_peer = db.query(WorkerIdentityRecord).filter_by(worker_id=peer_worker_id).one_or_none()
        except SQLAlchemyError:
            db.rollback()
            raise WorkerSecurityError("worker identity storage is unavailable") from None
        if current_peer is None:
            raise WorkerSecurityError("worker identity is unknown")
        cert = _check_registered_certificate(current_peer, self.ca_pem, self.crl_pem, now)
        try:
            signature = base64.urlsafe_b64decode(evidence.signature_b64url + "=" * (-len(evidence.signature_b64url) % 4))
            public_key = cert.public_key()
            signed_bytes = evidence.signed_bytes()
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
            elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                public_key.verify(signature, signed_bytes)
            else:
                raise WorkerSecurityError("worker key type is unsupported")
        except (InvalidSignature, ValueError, TypeError):
            raise WorkerSecurityError("worker health signature is invalid") from None
        payload_hash = hashlib.sha256(signed_bytes).hexdigest()
        return signed_bytes, payload_hash, current_peer, now

    def current_health(self, db: Session, *, worker_id: str, max_age: timedelta = timedelta(seconds=30)) -> str:
        registration = DatabaseWorkerRegistry(db, self).get_registration(worker_id)
        if (registration is None or registration.evidence_verified is not True
                or registration.observed_at is None):
            return "UNKNOWN"
        now = self.clock()
        age = now - registration.observed_at
        if age < timedelta(0) or age > max_age:
            return "UNKNOWN"
        return registration.health.value


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class DatabaseWorkerRegistry(WorkerRegistry):
    """Read-only adapter exposing only registered workers with validated health evidence."""

    def __init__(self, db: Session, service: WorkerCommunicationService | None = None):
        self.db = db
        self.service = service or WorkerCommunicationService()

    def get_registration(self, worker_id: str) -> WorkerRegistration | None:
        try:
            identity = self.db.query(WorkerIdentityRecord).filter_by(worker_id=worker_id).one_or_none()
            if identity is None:
                return None
            health = self.db.query(WorkerHealthRecord).filter_by(worker_id=worker_id).one_or_none()
            if health is None:
                return WorkerRegistration(worker_id, WorkerHealth.UNKNOWN)
            observed_at = _as_utc(health.observed_at)
            if not health.evidence_payload or not health.signature_b64url:
                return WorkerRegistration(worker_id, WorkerHealth.UNKNOWN, observed_at, False)
            payload = json.loads(health.evidence_payload)
            evidence = WorkerHealthEvidence(
                worker_id=payload["worker_id"], status=payload["status"],
                observed_at=datetime.fromisoformat(payload["observed_at"]),
                sequence=payload["sequence"], nonce=payload["nonce"],
                signature_b64url=health.signature_b64url,
            )
            signed_bytes, payload_hash, verified_identity, _ = self.service.verify_health_evidence(
                self.db, peer_worker_id=worker_id, evidence=evidence, require_fresh=False,
            )
            verified = (
                verified_identity.status == "ACTIVE"
                and hashlib.sha256(signed_bytes).hexdigest() == payload_hash == health.evidence_hash
                and evidence.status == health.status
                and evidence.sequence == health.sequence
                and _as_utc(evidence.observed_at) == observed_at
            )
            state = WorkerHealth.HEALTHY if verified and health.status == "HEALTHY" else WorkerHealth.UNHEALTHY
            return WorkerRegistration(worker_id, state, observed_at, evidence_verified=verified)
        except Exception:
            self.db.rollback()
            return WorkerRegistration(worker_id, WorkerHealth.UNKNOWN)

    def get_available_worker_id(self) -> str | None:
        try:
            identities = self.db.query(WorkerIdentityRecord.worker_id).filter_by(status="ACTIVE").order_by(
                WorkerIdentityRecord.worker_id.asc()
            ).all()
            now = self.service.clock()
            for (worker_id,) in identities:
                registration = self.get_registration(worker_id)
                if (registration is not None and registration.health is WorkerHealth.HEALTHY
                        and registration.evidence_verified is True and registration.observed_at is not None
                        and now.tzinfo is not None
                        and timedelta(0) <= now - registration.observed_at <= timedelta(seconds=30)):
                    return worker_id
            return None
        except Exception:
            self.db.rollback()
            return None


def certificate_from_asgi_scope(scope: dict) -> bytes:
    """Read peer cert only from the ASGI TLS extension; never from request headers."""
    extensions = scope.get("extensions")
    tls = extensions.get("tls") if isinstance(extensions, dict) else None
    cert = tls.get("client_cert") if isinstance(tls, dict) else None
    if not isinstance(cert, bytes) or not cert:
        raise WorkerSecurityError("mutual TLS client certificate is required")
    return cert
