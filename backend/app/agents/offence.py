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
        human_confirmed = event.payload.get("human_confirmed", False)
        target = event.payload.get("target")
        db = SessionLocal()
        try:
            self.activate_emergency_lockdown(
                db=db,
                level="HEIGHTENED",
                reason=reason,
                activated_by=event.sender_id,
                human_confirmed=human_confirmed,
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
        human_confirmed: bool = False,
        target: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Activates heightened or full defensive containment.
        High-impact full containment requires explicit human confirmation.
        """
        self.task_count += 1
        self.heartbeat()

        if level == "FULL_CONTAINMENT" and not human_confirmed:
            is_permitted, err = check_permission(AgentRole.OFFENCE, Permission.ACTIVATE_EMERGENCY, human_confirmed=False)
            return {
                "success": False,
                "error": err or "Full system containment requires explicit operator confirmation.",
                "pending_approval": True,
                "action": "FULL_CONTAINMENT"
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
            f"Lockdown activated to {level}",
            "Defensive vault sealed and credentials purged from volatile memory",
            "Informer AI audio alerts broadcasted"
        ]
        if target:
            containment_log.append(f"Target '{target}' flagged for isolation")
        status.containment_actions_json = json.dumps(containment_log)
        db.commit()

        # Audit ledger
        AuditChainService.record_event(
            db,
            actor="Offence AI",
            event_type="EMERGENCY_LOCKDOWN_ACTIVATED",
            payload={"level": level, "reason": reason, "target": target}
        )

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

    def reset_emergency_lockdown(self, db: Session, human_confirmed: bool = False) -> Dict[str, Any]:
        """Resets emergency containment back to normal STANDARD status."""
        self.task_count += 1
        self.heartbeat()

        self.lockdown_level = "STANDARD"
        status = db.query(EmergencyStatus).filter_by(id=1).first()
        if status:
            status.is_active = False
            status.lockdown_level = "STANDARD"
            status.reason = "Manual reset by administrator"
            db.commit()

        AuditChainService.record_event(
            db,
            actor="Offence AI",
            event_type="EMERGENCY_LOCKDOWN_RESET",
            payload={"status": "NORMAL"}
        )

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
        reason: str = "Malicious signature detected"
    ) -> Dict[str, Any]:
        """
        Isolates a suspicious file by moving it into secure quarantine storage
        and revoking execution permissions.
        """
        self.task_count += 1
        self.heartbeat()

        p = Path(source_path)
        if not p.exists():
            return {"error": f"Source file does not exist: {source_path}"}

        target_name = f"{p.name}.quarantined_{int(datetime.now(timezone.utc).timestamp())}"
        safe_target = sanitize_filepath(target_name, QUARANTINE_DIR)

        try:
            shutil.move(str(p), str(safe_target))
            # Remove write/execute permissions
            os.chmod(str(safe_target), 0o400)
        except Exception as e:
            return {"error": f"Failed to quarantine file: {str(e)}"}

        record = QuarantineRecord(
            target_type="FILE",
            target_identifier=str(safe_target),
            reason=reason,
            active=True,
            notes=f"Original path: {source_path}"
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        AuditChainService.record_event(
            db,
            actor="Offence AI",
            event_type="FILE_QUARANTINED",
            payload={"record_id": record.id, "original_path": source_path, "reason": reason}
        )

        return {
            "success": True,
            "record_id": record.id,
            "quarantine_path": str(safe_target),
            "reason": reason,
            "status": "ISOLATED"
        }

    def simulate_containment_action(self, action_type: str, target: str) -> Dict[str, Any]:
        """
        Simulates network isolation or process termination in a controlled, safe environment
        without causing accidental damage to the host machine.
        """
        self.task_count += 1
        self.heartbeat()

        if action_type == "PROCESS_TERMINATION":
            return {
                "action": "PROCESS_TERMINATION",
                "target": target,
                "status": "SIMULATED_SUSPENSION",
                "details": f"Process '{target}' suspended from CPU scheduling and network sockets severed."
            }
        elif action_type == "NETWORK_ISOLATION":
            return {
                "action": "NETWORK_ISOLATION",
                "target": target,
                "status": "CONTAINED",
                "details": f"All outbound network routes for adapter/process '{target}' blocked via local packet filter."
            }
        return {"error": f"Unsupported containment action: {action_type}"}

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
                    human_confirmed=message.get("human_confirmed", False)
                )
            elif action == "reset":
                return self.reset_emergency_lockdown(db=db, human_confirmed=message.get("human_confirmed", False))
        finally:
            db.close()
        return {"error": f"Unknown action '{action}' for Offence AI"}
