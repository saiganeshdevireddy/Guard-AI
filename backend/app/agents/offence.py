"""
Offence AI - Defensive Emergency-Response & Incident Containment Agent.

IMPORTANT SECURITY MANDATE:
Offence AI is strictly defensive. It never performs external network attacks,
intrusion, or counter-strikes. Its mandate is rapid local incident isolation,
defensive containment, quarantine enforcement, and recovery coordination.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, event_bus
from app.config import DATA_DIR
from app.core.audit_chain import AuditChainService
from app.core.permissions import AgentRole, Permission, check_permission
from app.core.security import sanitize_filepath
from app.database import EmergencyStatus, QuarantineRecord, SessionLocal
from app.services.human_approval import ApprovalError, HumanApprovalService

QUARANTINE_DIR = DATA_DIR / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


class OffenceAI(BaseAgent):
    """
    Defensive emergency-response coordinator executing incident isolation,
    process containment, quarantine actions, and system protection.
    """

    def __init__(self):
        super().__init__(
            agent_id="offence_ai",
            name="Offence AI (Emergency Response)",
            role="Defensive emergency response, incident containment, and quarantine coordination"
        )
        self.lockdown_level = "STANDARD"  # STANDARD, HEIGHTENED, FULL_CONTAINMENT

    def _register_event_handlers(self):
        event_bus.subscribe("TRIGGER_EMERGENCY_CONTAINMENT", self._on_emergency_trigger)

    def _on_emergency_trigger(self, event):
        reason = event.payload.get("reason", "Critical threat detected by automated agent")
        target = event.payload.get("target")
        db = SessionLocal()
        try:
            self.activate_emergency_lockdown(
                db=db,
                level="HEIGHTENED",
                reason=reason,
                activated_by=event.sender_id,
                target=target
            )
        finally:
            db.close()

    def activate_emergency_lockdown(
        self,
        db: Session,
        level: str = "HEIGHTENED",
        reason: str = "Active incident containment",
        activated_by: str = "Offence AI",
        target: Optional[str] = None,
        approval_id: str | None = None,
        user_id: str | None = None,
    ) -> Dict[str, Any]:
        """
        Activates heightened or full defensive containment.
        High-impact full containment requires explicit human confirmation.
        """
        self.task_count += 1
        self.heartbeat()

        if level not in {"HEIGHTENED", "FULL_CONTAINMENT"}:
            return {"success": False, "error": "Unsupported lockdown level."}
        previous_lockdown_level = self.lockdown_level

        try:
            HumanApprovalService().consume(
                db, approval_id=approval_id, user_id=user_id, action="EMERGENCY_ACTIVATE",
                target=target, payload={"level": level, "reason": reason, "target": target},
            )
        except ApprovalError as exc:
            return {
                "success": False, "error": str(exc), "pending_approval": True, "action": level,
            }

        self.lockdown_level = level
        status = db.query(EmergencyStatus).filter_by(id=1).first()
        if not status:
            status = EmergencyStatus(id=1)
            db.add(status)

        status.is_active = True
        status.activated_at = datetime.now(timezone.utc)
        status.activated_by = activated_by
        status.reason = reason
        status.lockdown_level = level
        
        containment_log = [
            f"Guard AI incident mode set to {level}",
            "Vault session locked in this Guard AI process",
            "Incident recorded in the local audit ledger",
            "No operating-system, process, or network isolation is performed by this prototype",
        ]
        if target:
            containment_log.append(f"Target '{target}' recorded for operator review")
        status.containment_actions_json = json.dumps(containment_log)
        # Audit ledger
        try:
            AuditChainService.record_event(
                db, actor="Offence AI", event_type="EMERGENCY_LOCKDOWN_ACTIVATED",
                payload={"level": level, "reason": reason, "target": target},
            )
        except Exception:
            db.rollback()
            self.lockdown_level = previous_lockdown_level
            return {"success": False, "error": "Required audit persistence failed; action was rolled back."}

        # Broadcast across agent bus
        self.emit_event(
            event_type="EMERGENCY_LOCKDOWN_ACTIVATED",
            payload={"level": level, "reason": reason, "target": target},
            severity="CRITICAL"
        )

        return {
            "success": True,
            "status": "ACTIVE",
            "level": level,
            "reason": reason,
            "actions_executed": containment_log
        }

    def reset_emergency_lockdown(self, db: Session, *, approval_id: str | None = None,
                                 user_id: str | None = None) -> Dict[str, Any]:
        """Resets emergency containment back to normal STANDARD status."""
        self.task_count += 1
        self.heartbeat()

        previous_lockdown_level = self.lockdown_level
        try:
            HumanApprovalService().consume(
                db, approval_id=approval_id, user_id=user_id, action="EMERGENCY_RESET",
                target=None, payload={},
            )
        except ApprovalError as exc:
            return {"success": False, "error": str(exc), "pending_approval": True}

        self.lockdown_level = "STANDARD"
        status = db.query(EmergencyStatus).filter_by(id=1).first()
        if status:
            status.is_active = False
            status.lockdown_level = "STANDARD"
            status.reason = "Manual reset by administrator"
        try:
            AuditChainService.record_event(db, actor="Offence AI", event_type="EMERGENCY_LOCKDOWN_RESET",
                                           payload={"status": "NORMAL"})
        except Exception:
            db.rollback()
            self.lockdown_level = previous_lockdown_level
            return {"success": False, "error": "Required audit persistence failed; action was rolled back."}

        self.emit_event(
            event_type="EMERGENCY_LOCKDOWN_RESET",
            payload={"message": "System containment returned to normal baseline"},
            severity="INFO"
        )

        return {"success": True, "status": "RESET", "level": "STANDARD"}

    def quarantine_file(
        self,
        db: Session,
        source_path: str,
        reason: str = "Malicious signature detected",
        *, approval_id: str | None = None, user_id: str | None = None,
    ) -> Dict[str, Any]:
        """
        Isolates a suspicious file by moving it into secure quarantine storage
        and revoking execution permissions.
        """
        self.task_count += 1
        self.heartbeat()

        try:
            HumanApprovalService().consume(
                db, approval_id=approval_id, user_id=user_id, action="FILE_QUARANTINE",
                target=source_path, payload={"source_path": source_path, "reason": reason},
            )
        except ApprovalError as exc:
            return {"error": str(exc), "pending_approval": True}

        p = Path(source_path)
        if not p.exists():
            db.rollback()
            return {"error": f"Source file does not exist: {source_path}"}

        target_name = f"{p.name}.quarantined_{int(datetime.now(timezone.utc).timestamp())}"
        safe_target = sanitize_filepath(target_name, QUARANTINE_DIR)

        try:
            shutil.move(str(p), str(safe_target))
            # Remove write/execute permissions
            os.chmod(str(safe_target), 0o400)
        except Exception as e:
            db.rollback()
            return {"error": f"Failed to quarantine file: {str(e)}"}

        record = QuarantineRecord(
            target_type="FILE",
            target_identifier=str(safe_target),
            reason=reason,
            active=True,
            notes=f"Original path: {source_path}"
        )
        db.add(record)
        try:
            db.flush()
            AuditChainService.record_event(
                db, actor="Offence AI", event_type="FILE_QUARANTINED",
                payload={"record_id": record.id, "original_path": source_path, "reason": reason},
            )
        except Exception:
            db.rollback()
            try:
                shutil.move(str(safe_target), str(p))
                os.chmod(str(p), 0o600)
            except Exception:
                return {"error": "Audit failed and file rollback failed; operator recovery is required."}
            return {"error": "Required audit persistence failed; quarantine was rolled back."}

        return {
            "success": True,
            "record_id": record.id,
            "quarantine_path": str(safe_target),
            "reason": reason,
            "status": "ISOLATED"
        }

    def simulate_containment_action(self, action_type: str, target: str, *, db: Session,
                                    approval_id: str | None = None, user_id: str | None = None) -> Dict[str, Any]:
        """
        Simulates network isolation or process termination in a controlled, safe environment
        without causing accidental damage to the host machine.
        """
        self.task_count += 1
        self.heartbeat()

        permission = "PROCESS_TERMINATE" if action_type == "PROCESS_TERMINATION" else "NETWORK_ISOLATE"
        try:
            HumanApprovalService().consume(
                db, approval_id=approval_id, user_id=user_id, action=permission,
                target=target, payload={"action_type": action_type, "target": target},
            )
        except ApprovalError as exc:
            return {"error": str(exc), "pending_approval": True}

        if action_type == "PROCESS_TERMINATION":
            result = {
                "action": "PROCESS_TERMINATION",
                "target": target,
                "status": "SIMULATED_SUSPENSION",
                "details": f"Simulation only: no process '{target}' was suspended and no sockets were changed."
            }
        elif action_type == "NETWORK_ISOLATION":
            result = {
                "action": "NETWORK_ISOLATION",
                "target": target,
                "status": "SIMULATED_NETWORK_ISOLATION",
                "details": f"Simulation only: no network routes or packet filters for '{target}' were changed."
            }
        else:
            db.rollback()
            return {"error": f"Unsupported containment action: {action_type}"}
        try:
            AuditChainService.record_event(db, actor="Offence AI", event_type="SIMULATED_CONTAINMENT",
                                           payload={"action_type": action_type, "target": target})
        except Exception:
            db.rollback()
            return {"error": "Required audit persistence failed; action was not recorded."}
        return result

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        action = message.get("action")
        db = SessionLocal()
        try:
            if action == "status":
                status = db.query(EmergencyStatus).filter_by(id=1).first()
                return {
                    "is_active": status.is_active if status else False,
                    "level": self.lockdown_level,
                    "reason": status.reason if status else "None"
                }
            elif action == "activate":
                return self.activate_emergency_lockdown(
                    db=db,
                    level=message.get("level", "HEIGHTENED"),
                    reason=message.get("reason", "Operator request"),
                    target=message.get("target")
                )
            elif action == "reset":
                return self.reset_emergency_lockdown(db=db)
        finally:
            db.close()
        return {"error": f"Unknown action '{action}' for Offence AI"}
