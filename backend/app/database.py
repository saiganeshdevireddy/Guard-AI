"""Database models and session management for Guard AI."""
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_agent = Column(String(64), index=True)  # e.g. "Finder AI", "Wi-Fi Agent"
    severity = Column(String(32), index=True)  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    category = Column(String(64), index=True)  # "URL", "FILE", "PHISHING", "NETWORK", "SPAM", "BEHAVIOR"
    indicator = Column(String(512), index=True)  # The URL, hash, SSID, or process name
    description = Column(Text)
    details_json = Column(Text, default="{}")  # Stored JSON string
    status = Column(String(32), default="DETECTED", index=True)  # DETECTED, ANALYZING, MITIGATED, QUARANTINED, DISMISSED
    resolution = Column(Text, nullable=True)

    @property
    def details(self) -> Dict[str, Any]:
        try:
            return json.loads(self.details_json or "{}")
        except Exception:
            return {}

    @details.setter
    def details(self, value: Dict[str, Any]):
        self.details_json = json.dumps(value)


class AuditEntry(Base):
    """Tamper-evident hash ledger for local security event history."""
    __tablename__ = "audit_entries"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    timestamp_str = Column(String(64), default="", index=True)
    event_type = Column(String(64), index=True)
    actor = Column(String(64), index=True)
    payload_hash = Column(String(64))  # SHA-256 of the event data
    prev_hash = Column(String(64))     # Previous block hash (chain integrity)
    block_hash = Column(String(64), unique=True, index=True)  # SHA-256(prev_hash + timestamp + actor + event_type + payload_hash)
    signature = Column(String(128), default="GUARD_AI_VERIFIED")
    verified = Column(Boolean, default=True)


class BlockchainAnchor(Base):
    """Receipt reference for a hash anchored to a configured local EVM chain."""
    __tablename__ = "blockchain_anchors"

    id = Column(Integer, primary_key=True, index=True)
    audit_entry_id = Column(Integer, nullable=False, unique=True, index=True)
    chain_id = Column(Integer, nullable=True)
    contract_address = Column(String(64), nullable=True)
    transaction_hash = Column(String(80), nullable=True)
    status = Column(String(16), nullable=False, default="PENDING", index=True)
    retry_count = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    anchored_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RevokedToken(Base):
    """Persistent denylist of JWT identifiers until each token expires."""
    __tablename__ = "revoked_tokens"

    jti = Column(String(128), primary_key=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class VaultItem(Base):
    """Cryptographic Maze secure segmented storage."""
    __tablename__ = "vault_items"

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String(128), index=True)
    category = Column(String(64), default="CREDENTIAL", index=True)  # NOTE, CREDENTIAL, RECOVERY, SECRET
    ciphertext_b64 = Column(Text, nullable=False)
    nonce_b64 = Column(String(64), nullable=False)
    salt_b64 = Column(String(64), nullable=False)
    tag_b64 = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_locked = Column(Boolean, default=True)


class AgentState(Base):
    """Live state, heartbeats, and telemetry of multi-agent modules."""
    __tablename__ = "agent_states"

    id = Column(String(64), primary_key=True)  # "controller", "finder", "defence", "offence", "informer", etc.
    name = Column(String(64), nullable=False)
    role = Column(String(128), nullable=False)
    status = Column(String(32), default="ACTIVE")  # ACTIVE, IDLE, BUSY, OFFLINE
    last_heartbeat = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    task_count = Column(Integer, default=0)
    metrics_json = Column(Text, default="{}")

    @property
    def metrics(self) -> Dict[str, Any]:
        try:
            return json.loads(self.metrics_json or "{}")
        except Exception:
            return {}

    @metrics.setter
    def metrics(self, value: Dict[str, Any]):
        self.metrics_json = json.dumps(value)


class QuarantineRecord(Base):
    """Defensive isolation & quarantine ledger."""
    __tablename__ = "quarantine_records"

    id = Column(Integer, primary_key=True, index=True)
    target_type = Column(String(32), index=True)  # "FILE", "URL", "PROCESS", "NETWORK"
    target_identifier = Column(String(512), index=True)
    reason = Column(Text)
    quarantined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    active = Column(Boolean, default=True, index=True)
    notes = Column(Text, nullable=True)


class EmergencyStatus(Base):
    """Offence AI emergency response state."""
    __tablename__ = "emergency_status"

    id = Column(Integer, primary_key=True, default=1)
    is_active = Column(Boolean, default=False)
    activated_at = Column(DateTime, nullable=True)
    activated_by = Column(String(64), nullable=True)
    reason = Column(Text, nullable=True)
    lockdown_level = Column(String(32), default="STANDARD")  # STANDARD, HEIGHTENED, FULL_CONTAINMENT
    containment_actions_json = Column(Text, default="[]")


def init_db():
    """Create all tables in the database."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Initialize default emergency status if not present
        if not db.query(EmergencyStatus).filter_by(id=1).first():
            db.add(EmergencyStatus(id=1, is_active=False))
            db.commit()
    finally:
        db.close()


def get_db():
    """Dependency for obtaining database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
