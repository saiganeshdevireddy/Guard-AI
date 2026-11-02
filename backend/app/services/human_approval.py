"""Persisted approval primitives for high-impact agent actions."""
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import HumanActionApproval


class ApprovalError(RuntimeError):
    pass


def payload_hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class HumanApprovalService:
    MIN_TTL_SECONDS = 15
    MAX_TTL_SECONDS = 600
    ACTION_PERMISSION = {
        "EMERGENCY_ACTIVATE": "emergency:write", "EMERGENCY_RESET": "emergency:write",
        "PROCESS_TERMINATE": "emergency:write", "NETWORK_ISOLATE": "emergency:write",
        "FILE_QUARANTINE": "emergency:write", "VAULT_ESCROW_RESTORE": "vault:write",
        "VAULT_UNLOCK": "vault:write", "VAULT_ITEM_DECRYPT": "vault:write",
        "VAULT_ESCROW_GENERATE": "vault:write",
    }

    @staticmethod
    def _write_lock(db: Session) -> None:
        connection = db.connection()
        if connection.dialect.name == "sqlite":
            raw = connection.connection.driver_connection
            if not raw.in_transaction:
                connection.exec_driver_sql("BEGIN IMMEDIATE")

    @staticmethod
    def _now(now=None):
        value = now or datetime.now(timezone.utc)
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ApprovalError("trusted approval clock is unavailable")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _db_utc(value):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @classmethod
    def _authorize_user(cls, user_id: str, action: str) -> None:
        permission = cls.ACTION_PERMISSION.get(action)
        if not permission:
            raise ApprovalError("action is not eligible for human approval")
        try:
            from app.config import settings
            from app.security.auth import ROLE_PERMISSIONS
            users = json.loads(settings.AUTH_USERS_JSON)
            user = next((entry for entry in users if entry.get("username") == user_id
                         and entry.get("active") is True), None)
            permissions = ROLE_PERMISSIONS.get(user.get("role"), set()) if user else set()
            if "*" not in permissions and permission not in permissions:
                raise ApprovalError("current user is not authorized for this action")
        except ApprovalError:
            raise
        except Exception:
            raise ApprovalError("current authorization state is unavailable") from None

    def request(self, db: Session, *, user_id: str, action: str, target: str | None, payload: dict,
                now=None) -> HumanActionApproval:
        self._authorize_user(user_id, action)
        current = self._now(now)
        from app.config import settings
        ttl_seconds = settings.HUMAN_APPROVAL_TTL_SECONDS
        if (not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool)
                or not self.MIN_TTL_SECONDS <= ttl_seconds <= self.MAX_TTL_SECONDS):
            raise ApprovalError("approval expiry configuration is invalid")
        record = HumanActionApproval(
            approval_id=secrets.token_urlsafe(32), user_id=user_id, action=action,
            target=target, payload_hash=payload_hash(payload), status="PENDING",
            created_at=current, expires_at=current + timedelta(seconds=ttl_seconds),
        )
        try:
            db.add(record)
            db.commit()
            db.refresh(record)
            return record
        except SQLAlchemyError:
            db.rollback()
            raise ApprovalError("approval storage is unavailable") from None

    def approve(self, db: Session, *, approval_id: str, user_id: str, now=None) -> None:
        current = self._now(now)
        try:
            self._write_lock(db)
            record = db.query(HumanActionApproval).filter_by(approval_id=approval_id).with_for_update().one_or_none()
            if (record is None or record.user_id != user_id or record.status != "PENDING"
                    or self._db_utc(record.expires_at) <= current):
                db.rollback()
                raise ApprovalError("approval is unavailable or expired")
            self._authorize_user(user_id, record.action)
            record.status = "APPROVED"
            record.approved_at = current
            db.commit()
        except ApprovalError:
            raise
        except SQLAlchemyError:
            db.rollback()
            raise ApprovalError("approval storage is unavailable") from None

    def revoke(self, db: Session, *, approval_id: str, user_id: str, now=None) -> None:
        current = self._now(now)
        try:
            self._write_lock(db)
            record = db.query(HumanActionApproval).filter_by(approval_id=approval_id).with_for_update().one_or_none()
            if record is None or record.user_id != user_id or record.status not in {"PENDING", "APPROVED"}:
                db.rollback()
                raise ApprovalError("approval cannot be revoked")
            record.status = "REVOKED"
            record.revoked_at = current
            db.commit()
        except ApprovalError:
            raise
        except SQLAlchemyError:
            db.rollback()
            raise ApprovalError("approval storage is unavailable") from None

    def consume(self, db: Session, *, approval_id: str | None, user_id: str | None,
                action: str, target: str | None, payload: dict, now=None) -> None:
        if not approval_id or not user_id:
            raise ApprovalError("server-verified human approval is required")
        self._authorize_user(user_id, action)
        current = self._now(now)
        try:
            self._write_lock(db)
            record = db.query(HumanActionApproval).filter_by(approval_id=approval_id).with_for_update().one_or_none()
            if (record is None or record.status != "APPROVED" or record.user_id != user_id
                    or record.action != action or record.target != target
                    or record.payload_hash != payload_hash(payload)
                    or self._db_utc(record.expires_at) <= current):
                db.rollback()
                raise ApprovalError("approval is expired, mismatched, revoked, or already used")
            record.status = "CONSUMED"
            record.consumed_at = current
            # Deliberately do not commit. The protected action and required audit
            # event must commit this row in the same transaction.
        except ApprovalError:
            raise
        except SQLAlchemyError:
            db.rollback()
            raise ApprovalError("approval storage is unavailable") from None
