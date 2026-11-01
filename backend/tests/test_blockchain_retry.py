"""Retry, duplicate, and offline behavior for optional local-chain anchoring."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.audit_chain import AuditChainService
from app.database import AuditEntry, Base, BlockchainAnchor
from app.services import blockchain_audit


def _session_factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def test_blockchain_failure_retries_are_bounded_and_persist_failed_state(monkeypatch):
    factory = _session_factory()
    db = factory()
    entry = AuditChainService.record_event(db, "test", "ANCHOR", {"safe": True})
    anchor = BlockchainAnchor(
        audit_entry_id=entry.id, contract_address="pending", status="PENDING", retry_count=0
    )
    db.add(anchor)
    db.commit()
    anchor_id = anchor.id
    db.close()

    calls = []

    def unavailable(*_args):
        calls.append(1)
        raise RuntimeError("local node unavailable")

    monkeypatch.setattr(blockchain_audit, "SessionLocal", factory)
    monkeypatch.setattr(blockchain_audit, "anchor_audit_hash", unavailable)
    monkeypatch.setattr(blockchain_audit.time, "sleep", lambda _seconds: None)
    blockchain_audit.process_anchor(anchor_id, max_attempts=3)

    result = factory().query(BlockchainAnchor).filter_by(id=anchor_id).one()
    assert len(calls) == 3
    assert result.retry_count == 3
    assert result.status == "FAILED"
    assert "unavailable" in result.last_error


def test_confirmation_is_idempotent_for_duplicate_background_jobs(monkeypatch):
    factory = _session_factory()
    db = factory()
    entry = AuditChainService.record_event(db, "test", "ANCHOR", {"safe": True})
    anchor = BlockchainAnchor(
        audit_entry_id=entry.id, contract_address="pending", status="CONFIRMED",
        chain_id=31337, transaction_hash="0x" + "a" * 64,
    )
    db.add(anchor)
    db.commit()
    anchor_id = anchor.id
    db.close()

    monkeypatch.setattr(blockchain_audit, "SessionLocal", factory)
    blockchain_audit.process_anchor(anchor_id)
    result = factory().query(BlockchainAnchor).filter_by(id=anchor_id).one()
    assert result.status == "CONFIRMED"
    assert result.retry_count == 0
