"""Durable persistence for worker termination, evidence and cleanup lifecycles."""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import BrowserSessionRecord, BrowserWorkerOperationRecord, WorkerIdentityRecord
from app.services.browser_session_manager import (
    BrowserSession,
    CleanupReceipt,
    SessionState,
    TerminationReceipt,
)
from app.services.worker_supervisor import (
    ConfiguredWorkerCommandVerifier,
    DatabaseWorkerMessageVerifier,
    TerminationCommand,
    WorkerCommandAcknowledgement,
)


class OperationStoreError(RuntimeError):
    """Safe public error for operation-store unavailability or state conflicts."""


class DatabaseSupervisorOperationStore:
    """SQLAlchemy store; each operation is committed with its session state update."""

    MAX_DELIVERY_ATTEMPTS = 3
    MAX_COMMAND_TTL_SECONDS = 30
    MAX_EVIDENCE_AGE_SECONDS = 30

    def __init__(self, session_factory, *, clock=None, command_verifier=None,
                 message_verifier=None, cleanup_verifier=None):
        self._session_factory = session_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._command_verifier = command_verifier or ConfiguredWorkerCommandVerifier.from_settings()
        self._message_verifier = message_verifier or DatabaseWorkerMessageVerifier(
            session_factory=session_factory,
        )
        self._cleanup_verifier = cleanup_verifier

    @staticmethod
    def _begin_write(db: Session) -> None:
        connection = db.connection()
        if connection.dialect.name == "sqlite":
            raw = connection.connection.driver_connection
            if not raw.in_transaction:
                connection.exec_driver_sql("BEGIN IMMEDIATE")

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def put(self, command: TerminationCommand, expected: BrowserSession, pending: BrowserSession) -> None:
        db = self._session_factory()
        try:
            if (not command.signing_key_id or not command.signature_b64url
                    or command.issued_at.tzinfo is None or command.expires_at.tzinfo is None
                    or command.expires_at <= command.issued_at
                    or command.expires_at - command.issued_at > timedelta(seconds=self.MAX_COMMAND_TTL_SECONDS)):
                raise OperationStoreError("termination command signature is required")
            now = self._clock()
            if (not isinstance(now, datetime) or now.tzinfo is None
                    or self._utc(command.issued_at) > self._utc(now)
                    or self._utc(command.expires_at) <= self._utc(now)):
                raise OperationStoreError("termination command is expired or has an invalid timestamp")
            try:
                command_verified = self._command_verifier.verify(command, now=self._utc(now))
            except Exception:
                command_verified = False
            if command_verified is not True:
                raise OperationStoreError("termination command signature is untrusted")
            self._begin_write(db)
            session = db.query(BrowserSessionRecord).filter_by(
                session_id=command.session_id, owner_id=command.owner_id,
            ).with_for_update().one_or_none()
            existing_command = db.query(BrowserWorkerOperationRecord).filter_by(
                operation_id=command.command_id,
            ).with_for_update().one_or_none()
            if existing_command is not None:
                same_command = (
                    existing_command.session_id == command.session_id
                    and existing_command.owner_id == command.owner_id
                    and existing_command.worker_id == command.worker_id
                    and existing_command.command_signature == command.signature_b64url
                    and existing_command.signing_key_id == command.signing_key_id
                )
                if (same_command and session is not None
                        and session.state == SessionState.TERMINATION_PENDING.value):
                    db.commit()
                    return
                raise OperationStoreError("operation ID was reused with different command data")
            if (session is None or session.state != expected.state.value
                    or session.worker_id != command.worker_id
                    or expected.session_id != command.session_id
                    or expected.owner_id != command.owner_id
                    or expected.worker_id != command.worker_id
                    or pending.state is not SessionState.TERMINATION_PENDING):
                raise OperationStoreError("session changed before termination command was stored")

            previous = db.query(BrowserWorkerOperationRecord).filter_by(
                session_id=command.session_id,
            ).order_by(BrowserWorkerOperationRecord.created_at.desc()).with_for_update().all()
            retry_count = 0
            active_statuses = {"PENDING_DELIVERY", "DELIVERED", "ACKNOWLEDGED", "TERMINATION_PENDING"}
            for operation in previous:
                if operation.status not in active_statuses:
                    continue
                if self._utc(operation.expires_at) > self._utc(command.issued_at):
                    raise OperationStoreError("a termination operation is already pending")
                operation.status = "EXPIRED"
                operation.recovery_state = "RETRY_ELIGIBLE"
                retry_count = max(retry_count, operation.retry_count + 1)
            if retry_count >= self.MAX_DELIVERY_ATTEMPTS:
                raise OperationStoreError("termination retry limit was reached")

            db.add(BrowserWorkerOperationRecord(
                operation_id=command.command_id,
                session_id=command.session_id,
                owner_id=command.owner_id,
                worker_id=command.worker_id,
                command_type="TERMINATE_SESSION",
                signing_key_id=command.signing_key_id,
                command_signature=command.signature_b64url,
                status="PENDING_DELIVERY",
                issued_at=self._utc(command.issued_at),
                expires_at=self._utc(command.expires_at),
                retry_count=retry_count,
                delivery_attempts=0,
                delivery_status="PENDING",
                acknowledgement_status="PENDING",
                termination_status="PENDING",
                cleanup_status="NOT_STARTED",
                recovery_state="DELIVERY_PENDING",
                created_at=self._utc(command.issued_at),
                updated_at=self._utc(command.issued_at),
            ))
            changed = db.execute(
                update(BrowserSessionRecord)
                .where(
                    BrowserSessionRecord.session_id == command.session_id,
                    BrowserSessionRecord.owner_id == command.owner_id,
                    BrowserSessionRecord.state == expected.state.value,
                    BrowserSessionRecord.worker_id == command.worker_id,
                )
                .values(state=pending.state.value, updated_at=self._utc(command.issued_at))
            )
            if changed.rowcount != 1:
                raise OperationStoreError("session changed before termination command was stored")
            db.commit()
        except (OperationStoreError, SQLAlchemyError, IntegrityError):
            db.rollback()
            raise OperationStoreError("termination operation could not be stored") from None
        finally:
            db.close()

    def get(self, command_id: str) -> TerminationCommand | None:
        db = self._session_factory()
        try:
            row = db.query(BrowserWorkerOperationRecord).filter_by(operation_id=command_id).one_or_none()
            if row is None:
                return None
            return TerminationCommand(
                command_id=row.operation_id,
                session_id=row.session_id,
                worker_id=row.worker_id,
                owner_id=row.owner_id,
                issued_at=self._utc(row.issued_at),
                expires_at=self._utc(row.expires_at),
                signing_key_id=row.signing_key_id,
                signature_b64url=row.command_signature,
            )
        except SQLAlchemyError:
            db.rollback()
            raise OperationStoreError("worker operation storage is unavailable") from None
        finally:
            db.close()

    def begin_delivery_attempt(self, command_id: str, now: datetime) -> bool:
        db = self._session_factory()
        try:
            if not isinstance(now, datetime) or now.tzinfo is None:
                return False
            self._begin_write(db)
            row = db.query(BrowserWorkerOperationRecord).filter_by(
                operation_id=command_id,
            ).with_for_update().one_or_none()
            if (row is None or row.status != "PENDING_DELIVERY"
                    or self._utc(row.expires_at) <= self._utc(now)
                    or row.delivery_attempts >= self.MAX_DELIVERY_ATTEMPTS):
                db.rollback()
                return False
            row.delivery_attempts += 1
            row.delivery_status = "ATTEMPTING"
            row.updated_at = self._utc(now)
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
        finally:
            db.close()

    def mark_delivered(self, command_id: str, now: datetime) -> bool:
        db = self._session_factory()
        try:
            self._begin_write(db)
            row = db.query(BrowserWorkerOperationRecord).filter_by(
                operation_id=command_id,
            ).with_for_update().one_or_none()
            if (row is None or row.status != "PENDING_DELIVERY" or row.delivery_attempts < 1
                    or now.tzinfo is None):
                db.rollback()
                return False
            if self._utc(row.expires_at) <= self._utc(now):
                db.rollback()
                return False
            row.delivery_status = "DELIVERED"
            row.status = "DELIVERED"
            row.updated_at = self._utc(now)
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
        finally:
            db.close()

    def record_acknowledgement(self, command_id: str, acknowledgement: WorkerCommandAcknowledgement) -> bool:
        db = self._session_factory()
        try:
            self._begin_write(db)
            row = db.query(BrowserWorkerOperationRecord).filter_by(
                operation_id=command_id,
            ).with_for_update().one_or_none()
            clock_now = self._clock()
            if not isinstance(clock_now, datetime) or clock_now.tzinfo is None:
                db.rollback()
                return False
            now = self._utc(clock_now)
            if (row is None or row.status not in {"DELIVERED", "PENDING_DELIVERY"}
                    or row.acknowledgement_status != "PENDING"
                    or row.delivery_attempts < 1
                    or self._utc(row.expires_at) <= now
                    or acknowledgement.command_id != command_id
                    or acknowledgement.session_id != row.session_id
                    or acknowledgement.worker_id != row.worker_id):
                db.rollback()
                return False
            identity = db.query(WorkerIdentityRecord).filter_by(
                worker_id=row.worker_id,
            ).with_for_update().one_or_none()
            if identity is None or identity.status != "ACTIVE":
                db.rollback()
                return False
            observed = self._utc(acknowledgement.observed_at)
            if (acknowledgement.observed_at.tzinfo is None
                    or not self._utc(row.issued_at) <= observed <= now < self._utc(row.expires_at)):
                db.rollback()
                return False
            command = TerminationCommand(
                command_id=row.operation_id,
                session_id=row.session_id,
                worker_id=row.worker_id,
                owner_id=row.owner_id,
                issued_at=self._utc(row.issued_at),
                expires_at=self._utc(row.expires_at),
                signing_key_id=row.signing_key_id,
                signature_b64url=row.command_signature,
            )
            try:
                verified = self._message_verifier.verify_acknowledgement(acknowledgement, command)
            except Exception:
                verified = False
            if verified is not True:
                db.rollback()
                return False
            row.acknowledgement_status = "ACCEPTED"
            row.acknowledgement_at = now
            row.acknowledgement_observed_at = self._utc(acknowledgement.observed_at)
            row.acknowledgement_signature = acknowledgement.signature_b64url
            row.status = "ACKNOWLEDGED"
            row.delivery_status = "DELIVERED"
            row.recovery_state = "AWAITING_TERMINATION_EVIDENCE"
            row.updated_at = now
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
        finally:
            db.close()

    def has_acknowledgement(self, command_id: str) -> bool:
        db = self._session_factory()
        try:
            return db.query(BrowserWorkerOperationRecord.acknowledgement_status).filter_by(
                operation_id=command_id,
            ).scalar() == "ACCEPTED"
        except SQLAlchemyError:
            db.rollback()
            return False
        finally:
            db.close()

    def consume_result(
        self, command_id: str, expected: BrowserSession, terminated: BrowserSession,
        receipt: TerminationReceipt,
    ) -> bool:
        db = self._session_factory()
        try:
            self._begin_write(db)
            session = db.query(BrowserSessionRecord).filter_by(
                session_id=expected.session_id, owner_id=expected.owner_id,
            ).with_for_update().one_or_none()
            operation = db.query(BrowserWorkerOperationRecord).filter_by(
                operation_id=command_id,
            ).with_for_update().one_or_none()
            if (session is None or operation is None
                    or session.state != SessionState.TERMINATION_PENDING.value
                    or operation.status != "ACKNOWLEDGED"
                    or operation.acknowledgement_status != "ACCEPTED"
                    or operation.session_id != receipt.session_id
                    or operation.worker_id != receipt.worker_id
                    or operation.owner_id != expected.owner_id
                    or operation.operation_id != receipt.operation_id
                    or operation.termination_evidence_verified
                    or terminated.state is not SessionState.TERMINATED):
                db.rollback()
                return False
            identity = db.query(WorkerIdentityRecord).filter_by(
                worker_id=operation.worker_id,
            ).with_for_update().one_or_none()
            if identity is None or identity.status != "ACTIVE":
                db.rollback()
                return False
            clock_now = self._clock()
            if not isinstance(clock_now, datetime) or clock_now.tzinfo is None:
                db.rollback()
                return False
            now = self._utc(clock_now)
            observed = self._utc(receipt.observed_at)
            if (receipt.observed_at.tzinfo is None
                    or not self._utc(operation.issued_at) <= observed <= now < self._utc(operation.expires_at)):
                db.rollback()
                return False
            try:
                verified = self._message_verifier.verify_termination_receipt(receipt, expected)
            except Exception:
                verified = False
            if verified is not True:
                db.rollback()
                return False
            operation.status = "TERMINATED"
            operation.termination_status = "VERIFIED"
            operation.termination_observed_at = self._utc(receipt.observed_at)
            operation.termination_signature = receipt.signature_b64url
            operation.termination_evidence_verified = True
            operation.recovery_state = "CLEANUP_REQUIRED"
            operation.updated_at = now
            session.state = terminated.state.value
            session.updated_at = now
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
        finally:
            db.close()

    def begin_cleanup(self, expected: BrowserSession, pending: BrowserSession) -> bool:
        db = self._session_factory()
        try:
            clock_now = self._clock()
            if not isinstance(clock_now, datetime) or clock_now.tzinfo is None:
                return False
            now = self._utc(clock_now)
            self._begin_write(db)
            session = db.query(BrowserSessionRecord).filter_by(
                session_id=expected.session_id, owner_id=expected.owner_id,
            ).with_for_update().one_or_none()
            operation = db.query(BrowserWorkerOperationRecord).filter_by(
                session_id=expected.session_id, status="TERMINATED",
            ).with_for_update().one_or_none()
            if (session is None or operation is None
                    or session.state != SessionState.TERMINATED.value
                    or pending.state is not SessionState.CLEANUP_PENDING):
                db.rollback()
                return False
            session.state = pending.state.value
            session.updated_at = now
            operation.status = "CLEANUP_PENDING"
            operation.cleanup_status = "PENDING"
            operation.cleanup_attempts = 1
            operation.recovery_state = "CLEANUP_PENDING"
            operation.updated_at = session.updated_at
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
        finally:
            db.close()

    def commit_cleanup(self, expected: BrowserSession, cleaned: BrowserSession, receipt: CleanupReceipt) -> bool:
        db = self._session_factory()
        try:
            self._begin_write(db)
            session = db.query(BrowserSessionRecord).filter_by(
                session_id=expected.session_id, owner_id=expected.owner_id,
            ).with_for_update().one_or_none()
            operation = db.query(BrowserWorkerOperationRecord).filter_by(
                session_id=expected.session_id, status="CLEANUP_PENDING",
            ).with_for_update().one_or_none()
            if (session is None or operation is None
                    or session.state != SessionState.CLEANUP_PENDING.value
                    or cleaned.state is not SessionState.CLEANUP_VERIFIED
                    or receipt.session_id != session.session_id
                    or receipt.worker_id != operation.worker_id
                    or receipt.operation_id != operation.operation_id
                    or receipt.resources_absent is not True
                    or receipt.runtime_terminated is not True
                    or receipt.temporary_storage_removed is not True
                    or receipt.session_data_removed is not True
                    or receipt.credentials_disposed is not True
                    or receipt.temporary_artifacts_removed is not True):
                db.rollback()
                return False
            clock_now = self._clock()
            if (not isinstance(clock_now, datetime) or clock_now.tzinfo is None
                    or not isinstance(receipt.verified_at, datetime) or receipt.verified_at.tzinfo is None):
                db.rollback()
                return False
            now = self._utc(clock_now)
            verified_at = self._utc(receipt.verified_at)
            if (verified_at > now
                    or (now - verified_at).total_seconds() > self.MAX_EVIDENCE_AGE_SECONDS):
                db.rollback()
                return False
            try:
                verified = (
                    self._cleanup_verifier is not None
                    and self._cleanup_verifier.verify_cleanup_receipt(receipt, expected) is True
                )
            except Exception:
                verified = False
            if not verified:
                db.rollback()
                return False
            operation.status = "CLEANUP_VERIFIED"
            operation.cleanup_status = "VERIFIED"
            operation.cleanup_evidence_json = json.dumps({
                "session_id": receipt.session_id,
                "worker_id": receipt.worker_id,
                "resources_absent": receipt.resources_absent,
                "runtime_terminated": receipt.runtime_terminated,
                "temporary_storage_removed": receipt.temporary_storage_removed,
                "session_data_removed": receipt.session_data_removed,
                "credentials_disposed": receipt.credentials_disposed,
                "temporary_artifacts_removed": receipt.temporary_artifacts_removed,
                "verified_at": verified_at.isoformat(),
                "signature_b64url": receipt.signature_b64url,
            }, sort_keys=True)
            operation.cleanup_evidence_verified = True
            operation.cleanup_evidence_signature = receipt.signature_b64url
            operation.recovery_state = "COMPLETE"
            operation.updated_at = now
            session.state = cleaned.state.value
            session.updated_at = now
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
        finally:
            db.close()

    def record_cleanup_failure(self, expected: BrowserSession, failed: BrowserSession) -> bool:
        return self._set_cleanup_state(expected, failed, "CLEANUP_FAILED", "FAILED")

    def retry_cleanup(self, expected: BrowserSession, pending: BrowserSession) -> bool:
        return self._set_cleanup_state(expected, pending, "CLEANUP_PENDING", "PENDING")

    def _set_cleanup_state(self, expected: BrowserSession, updated: BrowserSession, operation_state: str, cleanup_status: str) -> bool:
        db = self._session_factory()
        try:
            self._begin_write(db)
            session = db.query(BrowserSessionRecord).filter_by(
                session_id=expected.session_id, owner_id=expected.owner_id,
            ).with_for_update().one_or_none()
            operation = db.query(BrowserWorkerOperationRecord).filter_by(
                session_id=expected.session_id,
            ).order_by(BrowserWorkerOperationRecord.created_at.desc()).with_for_update().first()
            if (session is None or operation is None or session.state != expected.state.value
                    or updated.state.value != operation_state):
                db.rollback()
                return False
            if (operation_state == "CLEANUP_PENDING"
                    and operation.cleanup_attempts >= self.MAX_DELIVERY_ATTEMPTS):
                db.rollback()
                return False
            now = self._utc(self._clock())
            operation.status = operation_state
            operation.cleanup_status = cleanup_status
            if cleanup_status == "PENDING" and expected.state is SessionState.CLEANUP_FAILED:
                operation.retry_count += 1
                operation.cleanup_attempts += 1
            operation.recovery_state = cleanup_status
            operation.updated_at = now
            session.state = updated.state.value
            session.updated_at = now
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
        finally:
            db.close()

    def recoverable_operations(self) -> list[dict]:
        """Read pending/failed operations after restart without inferring success."""
        db = self._session_factory()
        try:
            rows = db.query(BrowserWorkerOperationRecord).filter(
                BrowserWorkerOperationRecord.status.in_([
                    "PENDING_DELIVERY", "DELIVERED", "ACKNOWLEDGED", "TERMINATION_PENDING",
                    "CLEANUP_PENDING", "CLEANUP_FAILED", "EXPIRED",
                ])
            ).order_by(BrowserWorkerOperationRecord.created_at.asc()).all()
            return [{
                "operation_id": row.operation_id,
                "session_id": row.session_id,
                "worker_id": row.worker_id,
                "status": row.status,
                "recovery_state": row.recovery_state,
                "retry_count": row.retry_count,
                "expires_at": self._utc(row.expires_at),
            } for row in rows]
        except SQLAlchemyError:
            db.rollback()
            raise OperationStoreError("worker operation recovery data is unavailable") from None
        finally:
            db.close()
