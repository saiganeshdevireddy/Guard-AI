"""
Tests for Tamper-Evident Cryptographic Audit Chain.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.audit_chain import AuditChainService
from app.database import AuditEntry, Base


def get_test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return TestingSession()


def test_audit_chain_recording_and_integrity():
    db = get_test_db()
    # Record 3 sequential events
    b1 = AuditChainService.record_event(db, actor="Finder AI", event_type="SCAN_URL", payload={"url": "https://safe.org"})
    b2 = AuditChainService.record_event(db, actor="Defence AI", event_type="VAULT_LOCK", payload={"reason": "Manual"})
    b3 = AuditChainService.record_event(db, actor="Offence AI", event_type="QUARANTINE", payload={"file": "test.exe"})

    assert b1.prev_hash == "0" * 64
    assert b2.prev_hash == b1.block_hash
    assert b3.prev_hash == b2.block_hash

    # Verify integrity
    report = AuditChainService.verify_integrity(db)
    assert report["valid"] is True
    assert report["block_count"] == 3
    assert report["compromised_id"] is None


def test_tamper_detection_on_database_modification():
    db = get_test_db()
    b1 = AuditChainService.record_event(db, actor="Admin", event_type="INIT", payload={"v": 1})
    b2 = AuditChainService.record_event(db, actor="Admin", event_type="MODIFY", payload={"v": 2})

    # Maliciously alter b1 payload hash in the database
    b1.payload_hash = "deadbeef" * 8
    db.commit()

    report = AuditChainService.verify_integrity(db)
    assert report["valid"] is False
    assert report["compromised_id"] == b1.id
    assert "Hash integrity failure" in report["message"]


def test_audit_chain_detects_interior_deletion():
    db = get_test_db()
    first = AuditChainService.record_event(db, "test", "ONE", {"n": 1})
    middle = AuditChainService.record_event(db, "test", "TWO", {"n": 2})
    AuditChainService.record_event(db, "test", "THREE", {"n": 3})
    db.delete(middle)
    db.commit()
    report = AuditChainService.verify_integrity(db)
    assert report["valid"] is False
    assert report["compromised_id"] is not None


def test_audit_chain_detects_reordered_links():
    db = get_test_db()
    first = AuditChainService.record_event(db, "test", "ONE", {"n": 1})
    second = AuditChainService.record_event(db, "test", "TWO", {"n": 2})
    original_first_id, original_second_id = first.id, second.id
    first.id = 999
    db.flush()
    second.id = original_first_id
    db.flush()
    first.id = original_second_id
    db.commit()
    report = AuditChainService.verify_integrity(db)
    assert report["valid"] is False


def test_audit_chain_cannot_detect_deleted_tail_without_external_checkpoint():
    db = get_test_db()
    AuditChainService.record_event(db, "test", "ONE", {"n": 1})
    last = AuditChainService.record_event(db, "test", "TWO", {"n": 2})
    db.delete(last)
    db.commit()
    # A local hash chain has no trusted reference to the removed final block.
    assert AuditChainService.verify_integrity(db)["valid"] is True
