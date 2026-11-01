"""
Base Agent and Event Bus architecture for Guard AI.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import uuid

class AgentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    IDLE = "IDLE"
    BUSY = "BUSY"
    OFFLINE = "OFFLINE"
    CONTAINMENT = "CONTAINMENT"


class AgentEvent:
    """Standard message passed across the Guard AI multi-agent bus."""
    def __init__(
        self,
        sender_id: str,
        event_type: str,
        payload: Dict[str, Any],
        recipient_id: Optional[str] = None,
        severity: str = "INFO"
    ):
        self.event_id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.sender_id = sender_id
        self.event_type = event_type
        self.payload = payload
        self.recipient_id = recipient_id  # None means broadcast to all
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "sender_id": self.sender_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "recipient_id": self.recipient_id,
            "severity": self.severity,
        }


class EventBus:
    """In-memory pub/sub communication bus connecting all agents."""
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[AgentEvent], None]]] = {}
        self._history: List[AgentEvent] = []

    def subscribe(self, event_type: str, callback: Callable[[AgentEvent], None]):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def publish(self, event: AgentEvent):
        self._history.append(event)
        # Keep recent 200 events in memory
        if len(self._history) > 200:
            self._history.pop(0)

        # Deliver to specific event subscribers
        if event.event_type in self._subscribers:
            for cb in self._subscribers[event.event_type]:
                try:
                    cb(event)
                except Exception as e:
                    print(f"Error delivering event {event.event_type} to subscriber: {e}")

        # Deliver to wildcard subscribers
        if "*" in self._subscribers:
            for cb in self._subscribers["*"]:
                try:
                    cb(event)
                except Exception as e:
                    print(f"Error delivering wildcard event to subscriber: {e}")

    def get_recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        return [evt.to_dict() for evt in self._history[-limit:]]


# Global Event Bus instance
event_bus = EventBus()


class BaseAgent(ABC):
    """Abstract base class for all Guard AI agents."""
    def __init__(self, agent_id: str, name: str, role: str):
        self.agent_id = agent_id
        self.name = name
        self.role = role
        self.status = AgentStatus.ACTIVE
        self.last_heartbeat = datetime.now(timezone.utc)
        self.task_count = 0
        self.metrics: Dict[str, Any] = {}
        self._register_event_handlers()

    def heartbeat(self):
        self.last_heartbeat = datetime.now(timezone.utc)

    def emit_event(self, event_type: str, payload: Dict[str, Any], severity: str = "INFO", recipient_id: Optional[str] = None):
        self.heartbeat()
        event = AgentEvent(
            sender_id=self.agent_id,
            event_type=event_type,
            payload=payload,
            recipient_id=recipient_id,
            severity=severity
        )
        event_bus.publish(event)

    def get_state(self) -> Dict[str, Any]:
        return {
            "id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "status": self.status.value,
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "task_count": self.task_count,
            "metrics": self.metrics,
        }

    @abstractmethod
    def _register_event_handlers(self):
        """Subscribe to relevant events from event_bus."""
        pass

    @abstractmethod
    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a direct agent task."""
        pass
