"""Database models and session management for Guard AI."""
import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    inspect,
    text,
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


class BrowserSessionRecord(Base):
    """Privacy-minimal authorization metadata; contains no URL or browser contents."""
    __tablename__ = "browser_sessions"
    __table_args__ = (
        UniqueConstraint("owner_id", "idempotency_key_hash", name="uq_browser_session_owner_idempotency"),
    )

    session_id = Column(String(64), primary_key=True)
    owner_id = Column(String(128), nullable=False, index=True)
    idempotency_key_hash = Column(String(64), nullable=False)
    state = Column(String(32), nullable=False, index=True)
    worker_id = Column(String(128), nullable=True)
    policy_version = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    authorized_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class WorkerIdentityRecord(Base):
    """Administratively enrolled worker certificate identity; no private key material."""
    __tablename__ = "worker_identities"

    worker_id = Column(String(128), primary_key=True)
    certificate_fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    certificate_pem = Column(Text, nullable=False)
    certificate_chain_pem = Column(Text, nullable=False)
    certificate_expires_at = Column(DateTime, nullable=False)
    status = Column(String(16), nullable=False, default="ACTIVE", index=True)
    registered_by = Column(String(128), nullable=False)
    registered_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    revoked_at = Column(DateTime, nullable=True)


class WorkerAuthorizationTicketRecord(Base):
    """One-time worker authorization ticket state; raw bearer token is never stored."""
    __tablename__ = "worker_authorization_tickets"
    __table_args__ = (
        UniqueConstraint("worker_id", "delivery_id_hash", name="uq_worker_ticket_delivery"),
        UniqueConstraint("session_id", name="uq_worker_ticket_session"),
    )

    ticket_id = Column(String(64), primary_key=True)
    jti_hash = Column(String(64), nullable=False, unique=True, index=True)
    delivery_id_hash = Column(String(64), nullable=False)
    key_id = Column(String(32), nullable=True)
    session_id = Column(String(64), nullable=False, index=True)
    worker_id = Column(String(128), nullable=False, index=True)
    subject_id = Column(String(128), nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    redeemed_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class WorkerHealthRecord(Base):
    """Latest cryptographically authenticated health report, separate from enrollment."""
    __tablename__ = "worker_health_records"

    worker_id = Column(String(128), primary_key=True)
    status = Column(String(16), nullable=False)
    observed_at = Column(DateTime, nullable=False)
    sequence = Column(Integer, nullable=False)
    evidence_hash = Column(String(64), nullable=False)
    evidence_payload = Column(Text, nullable=True)
    signature_b64url = Column(String(2048), nullable=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class WorkerSigningKeyState(Base):
    """Last active worker-ticket key identifier observed; never stores key material."""
    __tablename__ = "worker_signing_key_state"

    id = Column(Integer, primary_key=True, default=1)
    active_key_id = Column(String(32), nullable=False)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


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
    """Create tables and apply the repository's narrow additive schema updates."""
    Base.metadata.create_all(bind=engine)
    _ensure_browser_session_columns(engine)
    _ensure_worker_ticket_delivery_column(engine)
    _ensure_worker_ticket_key_id_column(engine)
    _ensure_worker_health_evidence_columns(engine)
    db = SessionLocal()
    try:
        # Initialize default emergency status if not present
        if not db.query(EmergencyStatus).filter_by(id=1).first():
            db.add(EmergencyStatus(id=1, is_active=False))
            db.commit()
    finally:
        db.close()


def _ensure_browser_session_columns(bind):
    """Add nullable lifecycle timestamps to existing databases without rebuilding tables.

    This is a narrow additive compatibility step because the project has no migration
    framework. Existing rows are retained and backfilled from their original creation
    timestamp; future schema changes should move to a versioned migration system.
    """
    expected = {
        "authorized_at": DateTime(),
        "updated_at": DateTime(),
    }
    with bind.begin() as connection:
        inspector = inspect(connection)
        if "browser_sessions" not in inspector.get_table_names():
            return
        existing = {column["name"] for column in inspector.get_columns("browser_sessions")}
        for name, column_type in expected.items():
            if name not in existing:
                type_sql = column_type.compile(dialect=bind.dialect)
                connection.execute(text(f'ALTER TABLE browser_sessions ADD COLUMN "{name}" {type_sql}'))
        connection.execute(text(
            "UPDATE browser_sessions SET authorized_at = created_at "
            "WHERE authorized_at IS NULL"
        ))
        connection.execute(text(
            "UPDATE browser_sessions SET updated_at = created_at WHERE updated_at IS NULL"
        ))


def _ensure_worker_ticket_delivery_column(bind):
    """Safely add retry identity and uniqueness without discarding legacy rows.

    SQLite and PostgreSQL provide transactional DDL for this additive migration. On
    other dialects we stop before changing the schema rather than risk a partial
    upgrade. Conflicting legacy rows are reported for operator resolution; this
    migration never chooses or deletes records automatically.
    """
    if bind.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError(
            "Worker ticket schema upgrade requires transactional SQLite or PostgreSQL "
            "DDL; back up the database and migrate it with a reviewed migration before startup."
        )
    with bind.begin() as connection:
        inspector = inspect(connection)
        if "worker_authorization_tickets" not in inspector.get_table_names():
            return
        columns = {column["name"] for column in inspector.get_columns("worker_authorization_tickets")}
        # Inspect conflicts before issuing ALTER TABLE. Some SQLite driver
        # configurations do not start a transaction for DDL unless explicitly
        # configured; preflight therefore guarantees legacy conflicts cannot
        # leave a half-upgraded table even on those configurations.
        duplicates = connection.execute(text(
            "SELECT session_id, COUNT(*) AS row_count FROM worker_authorization_tickets "
            "GROUP BY session_id HAVING COUNT(*) > 1 LIMIT 10"
        )).all()
        if duplicates:
            conflicts = ", ".join(f"{row.session_id} ({row.row_count} records)" for row in duplicates)
            raise RuntimeError(
                "Cannot add unique worker-ticket session constraint: legacy duplicate "
                f"session_id values found: {conflicts}. No records were deleted or selected. "
                "Back up the database, review each ticket/session authorization, resolve "
                "conflicts explicitly, then restart."
            )
        if "delivery_id_hash" in columns:
            delivery_duplicates = connection.execute(text(
                "SELECT worker_id, delivery_id_hash, COUNT(*) AS row_count "
                "FROM worker_authorization_tickets WHERE delivery_id_hash IS NOT NULL "
                "GROUP BY worker_id, delivery_id_hash "
                "HAVING COUNT(*) > 1 LIMIT 10"
            )).all()
            if delivery_duplicates:
                conflicts = ", ".join(
                    f"worker {row.worker_id} ({row.row_count} records)" for row in delivery_duplicates
                )
                raise RuntimeError(
                    "Cannot add unique worker-ticket delivery constraint: legacy duplicate "
                    f"worker/delivery records found: {conflicts}. No records were deleted or "
                    "selected. Back up the database, review and resolve the duplicate retry "
                    "records explicitly, then restart."
                )
        if "delivery_id_hash" not in columns:
            connection.execute(text(
                "ALTER TABLE worker_authorization_tickets ADD COLUMN delivery_id_hash VARCHAR(64)"
            ))
        # Also resume safely if a prior process stopped after adding the column
        # but before backfilling it.
        records = connection.execute(text(
            "SELECT ticket_id FROM worker_authorization_tickets WHERE delivery_id_hash IS NULL"
        )).all()
        for (ticket_id,) in records:
            value = hashlib.sha256(f"legacy-ticket:{ticket_id}".encode()).hexdigest()
            connection.execute(text(
                "UPDATE worker_authorization_tickets SET delivery_id_hash = :value "
                "WHERE ticket_id = :ticket_id"
            ), {"value": value, "ticket_id": ticket_id})
        duplicates = connection.execute(text(
            "SELECT session_id, COUNT(*) AS row_count FROM worker_authorization_tickets "
            "GROUP BY session_id HAVING COUNT(*) > 1 LIMIT 10"
        )).all()
        if duplicates:
            conflicts = ", ".join(f"{row.session_id} ({row.row_count} records)" for row in duplicates)
            raise RuntimeError(
                "Cannot add unique worker-ticket session constraint: legacy duplicate "
                f"session_id values found: {conflicts}. No records were deleted or selected. "
                "Back up the database, review each ticket/session authorization, resolve "
                "conflicts explicitly, then restart."
            )
        delivery_duplicates = connection.execute(text(
            "SELECT worker_id, delivery_id_hash, COUNT(*) AS row_count "
            "FROM worker_authorization_tickets GROUP BY worker_id, delivery_id_hash "
            "HAVING COUNT(*) > 1 LIMIT 10"
        )).all()
        if delivery_duplicates:
            conflicts = ", ".join(
                f"worker {row.worker_id} ({row.row_count} records)" for row in delivery_duplicates
            )
            raise RuntimeError(
                "Cannot add unique worker-ticket delivery constraint: legacy duplicate "
                f"worker/delivery records found: {conflicts}. No records were deleted or "
                "selected. Back up the database, review and resolve the duplicate retry "
                "records explicitly, then restart."
            )
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_worker_ticket_delivery "
            "ON worker_authorization_tickets (worker_id, delivery_id_hash)"
        ))
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_worker_ticket_session "
            "ON worker_authorization_tickets (session_id)"
        ))


def _ensure_worker_ticket_key_id_column(bind):
    """Add a nullable signing-key identifier for backwards-compatible ticket records."""
    with bind.begin() as connection:
        inspector = inspect(connection)
        if "worker_authorization_tickets" not in inspector.get_table_names():
            return
        columns = {column["name"] for column in inspector.get_columns("worker_authorization_tickets")}
        if "key_id" not in columns:
            connection.execute(text(
                "ALTER TABLE worker_authorization_tickets ADD COLUMN key_id VARCHAR(32)"
            ))


def _ensure_worker_health_evidence_columns(bind):
    """Add evidence needed to re-verify persisted health assertions on every read."""
    with bind.begin() as connection:
        inspector = inspect(connection)
        if "worker_health_records" not in inspector.get_table_names():
            return
        columns = {column["name"] for column in inspector.get_columns("worker_health_records")}
        if "evidence_payload" not in columns:
            connection.execute(text(
                "ALTER TABLE worker_health_records ADD COLUMN evidence_payload TEXT"
            ))
        if "signature_b64url" not in columns:
            connection.execute(text(
                "ALTER TABLE worker_health_records ADD COLUMN signature_b64url VARCHAR(2048)"
            ))


def get_db():
    """Dependency for obtaining database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
