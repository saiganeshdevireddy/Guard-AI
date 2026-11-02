"""
Controller AI - Central Orchestrator & Multi-Agent Coordinator.

Manages agent lifecycles, health monitoring, threat evaluation, defensive routing,
and permission enforcement across Guard AI.
"""
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, event_bus
from app.agents.defence import DefenceAI
from app.agents.finder import FinderAI
from app.agents.informer import InformerAI
from app.agents.offence import OffenceAI
from app.core.audit_chain import AuditChainService
from app.database import AgentState, SessionLocal, ThreatEvent
from app.agents.specialized.app_monitor_agent import ApplicationBehaviourAgent


class ControllerAI(BaseAgent):
    """
    Central Coordinator of the Guard AI platform.
    Oversees all agents, evaluates threat signals, coordinates defensive maneuvers,
    and enforces platform-wide permissions.
    """

    def __init__(self):
        super().__init__(
            agent_id="controller_ai",
            name="Controller AI",
            role="Central coordinator, threat severity evaluator, and defensive orchestrator"
        )
        # Instantiate primary agents
        self.finder = FinderAI()
        self.defence = DefenceAI()
        self.offence = OffenceAI()
        self.informer = InformerAI()
        self.app_monitor = ApplicationBehaviourAgent()

        # Agent registry
        self.agents: Dict[str, BaseAgent] = {
            self.agent_id: self,
            self.finder.agent_id: self.finder,
            self.defence.agent_id: self.defence,
            self.offence.agent_id: self.offence,
            self.informer.agent_id: self.informer,
            # Specialized agents registered via finder
            self.finder.phishing_agent.agent_id: self.finder.phishing_agent,
            self.finder.file_agent.agent_id: self.finder.file_agent,
            self.finder.wifi_agent.agent_id: self.finder.wifi_agent,
            self.finder.browser_agent.agent_id: self.finder.browser_agent,
            self.finder.spam_agent.agent_id: self.finder.spam_agent,
            self.app_monitor.agent_id: self.app_monitor,
        }

    def _register_event_handlers(self):
        event_bus.subscribe("THREAT_REPORT_SUBMITTED", self._on_threat_report_received)

    def _on_threat_report_received(self, event):
        payload = event.payload
        db = SessionLocal()
        try:
            self.process_threat_report(db, payload)
        finally:
            db.close()

    def evaluate_severity(self, raw_score: int) -> str:
        """Standardized severity mapping."""
        if raw_score >= 80:
            return "CRITICAL"
        elif raw_score >= 55:
            return "HIGH"
        elif raw_score >= 25:
            return "MEDIUM"
        return "LOW"

    def process_threat_report(self, db: Session, report_data: Dict[str, Any]) -> ThreatEvent:
        """
        Receives threat findings from Finder AI or specialized agents,
        evaluates severity, records immutable audit trails, and triggers defensive coordination.
        """
        self.task_count += 1
        self.heartbeat()

        source = report_data.get("source", "Finder AI")
        category = report_data.get("category", "GENERAL")
        indicator = report_data.get("indicator", "unknown")
        raw_score = report_data.get("score", 0)
        severity = self.evaluate_severity(raw_score)
        description = report_data.get("description", f"Threat indicator detected: {indicator}")
        details = report_data.get("details", {})

        # 1. Store Threat in Database
        threat = ThreatEvent(
            source_agent=source,
            severity=severity,
            category=category,
            indicator=indicator,
            description=description,
            details_json=json.dumps(details),
            status="DETECTED"
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)

        # 2. Tamper-evident cryptographic audit log
        AuditChainService.record_event(
            db,
            actor="Controller AI",
            event_type="THREAT_EVALUATED",
            payload={
                "threat_id": threat.id,
                "source": source,
                "severity": severity,
                "category": category,
                "indicator": indicator,
            }
        )

        # 3. Defensive Coordination Orchestration
        if severity in ["HIGH", "CRITICAL"]:
            # Command Defence AI to protect vault
            self.defence.lock_vault(reason=f"Controller defensive trigger for {severity} threat ({indicator})")

        if severity == "CRITICAL":
            # Automated detection must not impersonate operator approval. Keep
            # the incident visible and require a deliberate dashboard action.
            threat.status = "AWAITING_OPERATOR_REVIEW"
            db.commit()

        # 4. Notify Informer AI for voice briefing
        self.informer.generate_threat_briefing({
            "category": category,
            "severity": severity,
            "indicator": indicator,
            "description": description
        })

        return threat

    def sync_agent_states_to_db(self, db: Session):
        """Persists current in-memory agent statuses and metrics to SQLite."""
        for agent_id, agent in self.agents.items():
            state = db.query(AgentState).filter_by(id=agent_id).first()
            if not state:
                state = AgentState(id=agent_id, name=agent.name, role=agent.role)
                db.add(state)
            state.status = agent.status.value
            state.last_heartbeat = agent.last_heartbeat
            state.task_count = agent.task_count
            state.metrics_json = json.dumps(agent.metrics)
        db.commit()

    def get_all_agent_states(self) -> List[Dict[str, Any]]:
        """Returns live states for frontend dashboard."""
        self.heartbeat()
        return [agent.get_state() for agent in self.agents.values()]

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        action = message.get("action")
        if action == "status":
            return {
                "active_agents_count": len(self.agents),
                "agents": self.get_all_agent_states()
            }
        return {"error": f"Unknown action '{action}' for Controller AI"}


# Global singleton Controller AI instance
controller_ai = ControllerAI()
