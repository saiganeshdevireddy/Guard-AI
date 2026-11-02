"""
Defence AI - Cryptographic Vault, Key Separation & Sensitive Data Protection.

Enforces:
- Authenticated AES-256-GCM encryption with Cryptographic Maze key derivation.
- Automatic vault protection & lock state management upon elevated threat levels.
- Secure disaster recovery keys.
- Continuous integrity checking.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, event_bus
from app.core.audit_chain import AuditChainService
from app.core.crypto_maze import crypto_maze
from app.database import SessionLocal, VaultItem
from app.services.human_approval import ApprovalError, HumanApprovalService


class DefenceAI(BaseAgent):
    """
    Defensive security agent managing cryptographic keys, sensitive data vaults,
    encryption layers, and secure access policies.
    """

    def __init__(self):
        super().__init__(
            agent_id="defence_ai",
            name="Defence AI",
            role="Guards sensitive assets, enforces Cryptographic Maze encryption, and oversees vault integrity"
        )
        self.is_vault_locked: bool = True
        self.active_session_passphrase: Optional[str] = None
        # Browser-session policy is explicitly disabled until a trusted policy
        # configuration and independently verified worker are available.
        self._browser_session_policy_enabled: bool = False

    def browser_session_policy_enabled(self) -> bool:
        """Return Defence-owned server policy; this is never client-controlled."""
        return self._browser_session_policy_enabled is True

    def authorizes_browser_worker(self, registration, *, now: datetime, max_age) -> bool:
        """Defence independently rejects missing, revoked, unhealthy or stale worker evidence."""
        from app.services.browser_session_manager import WorkerHealth, WorkerRegistration

        if self.browser_session_policy_enabled() is not True:
            return False
        if not isinstance(registration, WorkerRegistration):
            return False
        if registration.health is not WorkerHealth.HEALTHY or registration.evidence_verified is not True:
            return False
        if registration.observed_at is None or registration.observed_at.tzinfo is None or now.tzinfo is None:
            return False
        try:
            age = now - registration.observed_at
        except (TypeError, OverflowError):
            return False
        return timedelta(0) <= age <= max_age

    def _register_event_handlers(self):
        # Listen for elevated threat alerts to trigger immediate protective lockdown
        event_bus.subscribe("THREAT_REPORT_SUBMITTED", self._on_threat_detected)
        event_bus.subscribe("EMERGENCY_LOCKDOWN_ACTIVATED", self._on_emergency_lockdown)

    def _on_threat_detected(self, event):
        severity = event.payload.get("severity")
        if severity in ["HIGH", "CRITICAL"]:
            self.lock_vault(reason=f"Elevated threat detected ({severity})")

    def _on_emergency_lockdown(self, event):
        self.lock_vault(reason="Emergency lockdown initiated by Offence AI / Controller")

    def lock_vault(self, reason: str = "Manual lock"):
        """Purges cached credentials from memory and seals vault."""
        self.is_vault_locked = True
        self.active_session_passphrase = None
        self.heartbeat()
        self.emit_event(
            event_type="VAULT_LOCKED",
            payload={"reason": reason, "timestamp": datetime.now(timezone.utc).isoformat()},
            severity="WARNING"
        )

    def unlock_vault(self, passphrase: str, db: Session, *, approval_id: str | None = None,
                     user_id: str | None = None) -> Dict[str, Any]:
        """
        Verifies passphrase against a test/canary item or unlocks session for subsequent operations.
        """
        self.task_count += 1
        self.heartbeat()
        try:
            HumanApprovalService().consume(db, approval_id=approval_id, user_id=user_id,
                                           action="VAULT_UNLOCK", target="vault",
                                           payload={"passphrase": passphrase})
        except ApprovalError as exc:
            return {"success": False, "message": str(exc), "pending_approval": True}

        # In a real vault, we verify passphrase against canary or existing items
        first_item = db.query(VaultItem).first()
        if first_item:
            try:
                crypto_maze.decrypt_segmented(
                    {
                        "salt_b64": first_item.salt_b64,
                        "nonce_b64": first_item.nonce_b64,
                        "ciphertext_b64": first_item.ciphertext_b64,
                        "tag_b64": first_item.tag_b64,
                        "label": first_item.label,
                    },
                    passphrase=passphrase
                )
            except ValueError:
                AuditChainService.record_event(
                    db, actor="Defence AI", event_type="VAULT_UNLOCK_FAILED",
                    payload={"reason": "Incorrect passphrase attempt"}
                )
                return {"success": False, "message": "Authentication failed: Invalid passphrase."}

        previous_locked, previous_passphrase = self.is_vault_locked, self.active_session_passphrase
        self.is_vault_locked = False
        self.active_session_passphrase = passphrase

        try:
            AuditChainService.record_event(db, actor="Defence AI", event_type="VAULT_UNLOCKED",
                                           payload={"status": "UNLOCKED"})
        except Exception:
            db.rollback()
            self.is_vault_locked, self.active_session_passphrase = previous_locked, previous_passphrase
            return {"success": False, "message": "Required audit persistence failed; vault remains locked."}
        return {"success": True, "message": "Cryptographic Vault unlocked successfully."}

    def encrypt_and_store_secret(
        self,
        db: Session,
        label: str,
        plaintext: str,
        passphrase: str,
        category: str = "CREDENTIAL"
    ) -> Dict[str, Any]:
        """
        Stores encrypted secret using Cryptographic Maze layered AEAD encryption.
        """
        self.task_count += 1
        self.heartbeat()

        encrypted_pack = crypto_maze.encrypt_segmented(
            plaintext=plaintext,
            passphrase=passphrase,
            label=label,
        )

        item = VaultItem(
            label=label,
            category=category,
            ciphertext_b64=encrypted_pack["ciphertext_b64"],
            nonce_b64=encrypted_pack["nonce_b64"],
            salt_b64=encrypted_pack["salt_b64"],
            tag_b64=encrypted_pack["tag_b64"],
            is_locked=True
        )
        db.add(item)
        db.commit()
        db.refresh(item)

        AuditChainService.record_event(
            db,
            actor="Defence AI",
            event_type="VAULT_ITEM_STORED",
            payload={"item_id": item.id, "label": label, "category": category}
        )

        return {
            "id": item.id,
            "label": item.label,
            "category": item.category,
            "created_at": item.created_at.isoformat(),
            "status": "SECURED_AES_256_GCM"
        }

    def decrypt_secret(
        self,
        db: Session,
        item_id: int,
        passphrase: str,
        *, approval_id: str | None = None, user_id: str | None = None,
    ) -> Dict[str, Any]:
        """
        Retrieves and decrypts a vault item.
        """
        self.task_count += 1
        self.heartbeat()

        item = db.query(VaultItem).filter(VaultItem.id == item_id).first()
        if not item:
            return {"error": "Vault item not found"}

        try:
            HumanApprovalService().consume(
                db, approval_id=approval_id, user_id=user_id, action="VAULT_ITEM_DECRYPT",
                target=str(item_id), payload={"item_id": item_id, "passphrase": passphrase},
            )
        except ApprovalError as exc:
            return {"error": str(exc), "pending_approval": True}

        try:
            plaintext = crypto_maze.decrypt_segmented(
                {
                    "salt_b64": item.salt_b64,
                    "nonce_b64": item.nonce_b64,
                    "ciphertext_b64": item.ciphertext_b64,
                    "tag_b64": item.tag_b64,
                    "label": item.label,
                },
                passphrase=passphrase
            )

            AuditChainService.record_event(
                db,
                actor="Defence AI",
                event_type="VAULT_ITEM_DECRYPTED",
                payload={"item_id": item.id, "label": item.label}
            )

            return {
                "id": item.id,
                "label": item.label,
                "category": item.category,
                "plaintext": plaintext,
                "verified": True,
            }
        except ValueError as e:
            AuditChainService.record_event(
                db,
                actor="Defence AI",
                event_type="VAULT_DECRYPTION_TAMPER_ALERT",
                payload={"item_id": item.id, "error": str(e)}
            )
            return {"error": str(e), "verified": False}

    def generate_escrow_backup(self, payload: str, *, db: Session, approval_id: str | None = None,
                               user_id: str | None = None) -> Dict[str, str]:
        """Generates emergency disaster recovery token via Fernet envelope."""
        try:
            HumanApprovalService().consume(db, approval_id=approval_id, user_id=user_id,
                                           action="VAULT_ESCROW_GENERATE", target="vault",
                                           payload={"payload": payload})
        except ApprovalError:
            return {"error": "Server-verified approval is required."}
        try:
            key, token = crypto_maze.generate_recovery_token(payload)
            AuditChainService.record_event(db, actor="Defence AI", event_type="VAULT_ESCROW_GENERATED",
                                           payload={"result": "success"})
        except Exception:
            db.rollback()
            return {"error": "Escrow generation could not be safely recorded."}
        return {
            "recovery_key": key,
            "encrypted_token": token,
            "instructions": "Store the recovery key in an isolated physical vault or offline medium."
        }

    def restore_escrow_backup(self, recovery_key: str, encrypted_token: str, *, db: Session,
                              approval_id: str | None = None, user_id: str | None = None) -> str:
        """Restore only under a user-bound approval; never persist secrets in the audit payload."""
        HumanApprovalService().consume(
            db, approval_id=approval_id, user_id=user_id, action="VAULT_ESCROW_RESTORE", target="vault",
            payload={"recovery_key": recovery_key, "encrypted_token": encrypted_token},
        )
        try:
            restored = crypto_maze.restore_from_recovery_token(recovery_key, encrypted_token)
            AuditChainService.record_event(db, actor="Defence AI", event_type="VAULT_ESCROW_RESTORED",
                                           payload={"result": "success", "approval_id": approval_id})
            return restored
        except Exception:
            db.rollback()
            raise

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        action = message.get("action")
        db = SessionLocal()
        try:
            if action == "lock":
                self.lock_vault()
                return {"status": "LOCKED"}
            elif action == "status":
                item_count = db.query(VaultItem).count()
                return {
                    "is_locked": self.is_vault_locked,
                    "vault_items_count": item_count,
                    "algorithm": "AES-256-GCM + PBKDF2-HMAC-SHA256"
                }
        finally:
            db.close()
        return {"error": f"Unknown action '{action}' for Defence AI"}
