"""
Defensive Emergency Response & Incident Containment API Router.
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.agents.controller import controller_ai
from app.database import EmergencyStatus, QuarantineRecord, get_db
from app.security.auth import require_permission

router = APIRouter(prefix="/emergency", tags=["Emergency Response"])


class ActivateLockdownRequest(BaseModel):
    level: str = "HEIGHTENED"  # HEIGHTENED or FULL_CONTAINMENT
    reason: str = "Operator emergency activation"
    human_confirmed: bool = False
    target: Optional[str] = None


class ResetLockdownRequest(BaseModel):
    human_confirmed: bool = False


class SimulateContainmentRequest(BaseModel):
    action_type: str  # PROCESS_TERMINATION, NETWORK_ISOLATION
    target: str


@router.get("/status")
def get_emergency_status(db: Session = Depends(get_db), _user=Depends(require_permission("emergency:read"))):
    """Returns the current defensive lockdown level and active containment actions."""
    status = db.query(EmergencyStatus).filter_by(id=1).first()
    return {
        "is_active": status.is_active if status else False,
        "lockdown_level": status.lockdown_level if status else "STANDARD",
        "reason": status.reason if status else "None",
        "activated_at": status.activated_at.isoformat() if (status and status.activated_at) else None,
        "activated_by": status.activated_by if status else None,
        "containment_actions": status.containment_actions_json if status else "[]",
    }


@router.post("/activate")
def activate_lockdown(req: ActivateLockdownRequest, db: Session = Depends(get_db), _user=Depends(require_permission("emergency:write"))):
    """Activates heightened or full containment mode. High impact requires operator confirmation."""
    res = controller_ai.offence.activate_emergency_lockdown(
        db=db,
        level=req.level,
        reason=req.reason,
        activated_by="Operator / Offence AI",
        human_confirmed=req.human_confirmed,
        target=req.target
    )
    if not res["success"]:
        raise HTTPException(status_code=403, detail=res["error"])
    return res


@router.post("/reset")
def reset_lockdown(req: ResetLockdownRequest, db: Session = Depends(get_db), _user=Depends(require_permission("emergency:write"))):
    """Resets containment back to normal standard operating status."""
    result = controller_ai.offence.reset_emergency_lockdown(db=db, human_confirmed=req.human_confirmed)
    if not result["success"]:
        raise HTTPException(status_code=403, detail=result["error"])
    return result


@router.get("/quarantine")
def list_quarantine_records(db: Session = Depends(get_db), _user=Depends(require_permission("emergency:read"))):
    """Lists all files and artifacts currently held in isolated quarantine storage."""
    records = db.query(QuarantineRecord).order_by(QuarantineRecord.id.desc()).all()
    return {
        "quarantined_items": [
            {
                "id": r.id,
                "target_type": r.target_type,
                "target_identifier": r.target_identifier,
                "reason": r.reason,
                "quarantined_at": r.quarantined_at.isoformat() if r.quarantined_at else "",
                "active": r.active,
                "notes": r.notes,
            }
            for r in records
        ],
        "count": len(records)
    }


@router.post("/simulate-containment")
def simulate_containment(req: SimulateContainmentRequest, _user=Depends(require_permission("emergency:write"))):
    """Safely simulates process suspension or network cutoff in a controlled sandbox."""
    return controller_ai.offence.simulate_containment_action(req.action_type, req.target)
