"""Compact event pipeline built on Guard AI's existing agents and audit chain."""
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.agents.controller import controller_ai
from app.core.audit_chain import AuditChainService
from app.database import get_db

router = APIRouter(tags=["Pipeline"])


class PipelineEvent(BaseModel):
    type: Literal["link", "download", "wifi"]
    value: str = Field(min_length=1, max_length=2048)
    source: str = Field(min_length=1, max_length=128)


@router.post("/api/pipeline/event")
def pipeline_event(event: PipelineEvent, db: Session = Depends(get_db)):
    # URL phishing analysis is the existing Finder sub-agent used by scan_url.
    analysis = controller_ai.finder.phishing_agent.analyze_url(event.value)
    score = analysis["score"]
    verdict = "Danger" if score >= 60 else "Careful" if score >= 25 else "Safe"
    severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 55 else "MEDIUM" if score >= 25 else "LOW"

    # Ask the existing controller for its severity policy; never execute its
    # high-impact vault lockdown here without a server-side approval ticket.
    policy_severity = controller_ai.evaluate_severity(score)
    action = "block" if verdict == "Danger" else "warn" if verdict == "Careful" else "allow"
    controller_result = {"severity": policy_severity, "policy": action}
    defence_result = "Blocked automatically" if action == "block" else f"No automatic block; {action}"
    if severity in {"HIGH", "CRITICAL"}:
        defence_result += "; lockdown SIMULATED, waiting for approval"

    briefing = controller_ai.informer.generate_threat_briefing({
        "category": "NETWORK" if event.type == "wifi" else "URL",
        "severity": severity,
        "indicator": event.value,
        "description": f"{event.type} event reported by {event.source}",
    })
    spoken = briefing["spoken_text"]
    telugu = {
        "Safe": "ఈ లింక్ సురక్షితంగా కనిపిస్తోంది. జాగ్రత్తగా కొనసాగండి.",
        "Careful": "ఈ లింక్‌లో అనుమానాస్పద లక్షణాలు ఉన్నాయి. తెరవడానికి ముందు పరిశీలించండి.",
        "Danger": "ప్రమాదకరమైన లింక్ బ్లాక్ చేయబడింది. దీన్ని తెరవవద్దు.",
    }[verdict]

    steps = [
        {"name": "Finder", "result": {"verdict": verdict, "score": score, "analysis": analysis}, "status": "automatic"},
        {"name": "Controller", "result": controller_result, "status": "automatic"},
        {"name": "Defence", "result": defence_result, "status": "automatic"},
        {"name": "Informer", "result": {"english": spoken, "telugu": telugu}, "status": "automatic"},
    ]
    for step in steps:
        entry = AuditChainService.record_event(
            db, actor="Pipeline", event_type="PIPELINE_STEP",
            payload={"source": event.source, "type": event.type, "step": step["name"], "result": step["result"], "status": step["status"]},
        )
        step["audit_entry_id"] = entry.id
    audit_step = {"name": "Audit", "result": "All pipeline steps written to the audit chain", "status": "automatic"}
    entry = AuditChainService.record_event(
        db, actor="Pipeline", event_type="PIPELINE_STEP",
        payload={"source": event.source, "type": event.type, "step": audit_step["name"], "result": audit_step["result"]},
    )
    audit_step["audit_entry_id"] = entry.id
    steps.append(audit_step)
    return {"verdict": verdict, "action": action, "steps": steps}
