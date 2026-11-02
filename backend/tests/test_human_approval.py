from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import secrets
import threading

import pytest

from app.agents.offence import OffenceAI
from app.core.audit_chain import AuditChainService
from app.database import EmergencyStatus, SessionLocal, init_db
from app.services.human_approval import ApprovalError, HumanApprovalService
from app.config import settings
import json


init_db()
service = HumanApprovalService()
USER = json.loads(settings.AUTH_USERS_JSON)[0]["username"]


def _approval(action, target, payload, *, user=USER, now=None):
    db = SessionLocal()
    try:
        record = service.request(db, user_id=user, action=action, target=target, payload=payload, now=now)
        service.approve(db, approval_id=record.approval_id, user_id=user,
                        now=(now + timedelta(seconds=1)) if now else None)
        return record.approval_id
    finally:
        db.close()


def test_approval_is_bound_single_use_and_rejects_user_action_and_payload_mismatch():
    now = datetime.now(timezone.utc)
    approval_id = _approval("EMERGENCY_ACTIVATE", "host-a",
                            {"level": "HEIGHTENED", "reason": "incident", "target": "host-a"}, now=now)
    db = SessionLocal()
    try:
        with pytest.raises(ApprovalError):
            service.consume(db, approval_id=approval_id, user_id="another-user", action="EMERGENCY_ACTIVATE",
                            target="host-a", payload={"level": "HEIGHTENED", "reason": "incident", "target": "host-a"}, now=now + timedelta(seconds=2))
        with pytest.raises(ApprovalError):
            service.consume(db, approval_id=approval_id, user_id=USER, action="EMERGENCY_RESET",
                            target="host-a", payload={}, now=now + timedelta(seconds=2))
        with pytest.raises(ApprovalError):
            service.consume(db, approval_id=approval_id, user_id=USER, action="EMERGENCY_ACTIVATE",
                            target="host-a", payload={"level": "FULL_CONTAINMENT", "reason": "incident", "target": "host-a"}, now=now + timedelta(seconds=2))
        service.consume(db, approval_id=approval_id, user_id=USER, action="EMERGENCY_ACTIVATE",
                        target="host-a", payload={"level": "HEIGHTENED", "reason": "incident", "target": "host-a"}, now=now + timedelta(seconds=2))
        db.commit()
        with pytest.raises(ApprovalError):
            service.consume(db, approval_id=approval_id, user_id=USER, action="EMERGENCY_ACTIVATE",
                            target="host-a", payload={"level": "HEIGHTENED", "reason": "incident", "target": "host-a"}, now=now + timedelta(seconds=3))
    finally:
        db.close()


def test_expired_and_revoked_approvals_are_denied():
    now = datetime.now(timezone.utc)
    expired = _approval("EMERGENCY_RESET", None, {}, now=now - timedelta(minutes=3))
    revoked = _approval("EMERGENCY_RESET", None, {})
    db = SessionLocal()
    try:
        service.revoke(db, approval_id=revoked, user_id=USER)
        with pytest.raises(ApprovalError):
            service.consume(db, approval_id=expired, user_id=USER, action="EMERGENCY_RESET", target=None, payload={})
        with pytest.raises(ApprovalError):
            service.consume(db, approval_id=revoked, user_id=USER, action="EMERGENCY_RESET", target=None, payload={})
    finally:
        db.close()


def test_concurrent_consumption_allows_exactly_one_winner():
    approval_id = _approval("NETWORK_ISOLATE", "net-a", {"action_type": "NETWORK_ISOLATION", "target": "net-a"})
    barrier = threading.Barrier(2)

    def consume():
        db = SessionLocal()
        try:
            barrier.wait(timeout=5)
            service.consume(db, approval_id=approval_id, user_id=USER, action="NETWORK_ISOLATE",
                            target="net-a", payload={"action_type": "NETWORK_ISOLATION", "target": "net-a"})
            db.commit()
            return True
        except ApprovalError:
            return False
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))
    assert sum(results) == 1


def test_offence_direct_calls_require_approval_and_valid_activation_is_audited():
    offence = OffenceAI()
    db = SessionLocal()
    try:
        denied = offence.activate_emergency_lockdown(db, level="HEIGHTENED", reason="test", target="host-b")
        assert not denied["success"]
        approval_id = _approval("EMERGENCY_ACTIVATE", "host-b",
                                {"level": "HEIGHTENED", "reason": "test", "target": "host-b"})
        allowed = offence.activate_emergency_lockdown(
            db, level="HEIGHTENED", reason="test", target="host-b", approval_id=approval_id, user_id=USER,
        )
        assert allowed["success"]
        status = db.query(EmergencyStatus).filter_by(id=1).one()
        assert status.is_active
    finally:
        db.close()


def test_offence_reset_direct_call_requires_approval():
    offence = OffenceAI()
    db = SessionLocal()
    try:
        assert not offence.reset_emergency_lockdown(db)["success"]
        approval_id = _approval("EMERGENCY_RESET", None, {})
        result = offence.reset_emergency_lockdown(db, approval_id=approval_id, user_id=USER)
        assert result["success"]
    finally:
        db.close()


def test_audit_failure_rolls_back_approval_and_emergency_state(monkeypatch):
    offence = OffenceAI()
    setup = SessionLocal()
    try:
        setup.query(EmergencyStatus).filter_by(id=1).delete()
        setup.commit()
    finally:
        setup.close()
    approval_id = _approval("EMERGENCY_ACTIVATE", None,
                            {"level": "HEIGHTENED", "reason": "test", "target": None})
    def fail_audit(*_args, **_kwargs):
        raise RuntimeError("injected audit failure")
    monkeypatch.setattr(AuditChainService, "record_event", fail_audit)
    db = SessionLocal()
    try:
        result = offence.activate_emergency_lockdown(
            db, level="HEIGHTENED", reason="test", approval_id=approval_id, user_id=USER,
        )
        assert not result["success"]
        assert db.query(EmergencyStatus).filter_by(id=1).first() is None
    finally:
        db.close()


def test_simulated_containment_and_file_quarantine_require_bound_approval(tmp_path):
    offence = OffenceAI()
    db = SessionLocal()
    try:
        assert "error" in offence.simulate_containment_action("PROCESS_TERMINATION", "pid:123", db=db)
        approval_id = _approval("PROCESS_TERMINATE", "pid:123",
                                {"action_type": "PROCESS_TERMINATION", "target": "pid:123"})
        result = offence.simulate_containment_action("PROCESS_TERMINATION", "pid:123", db=db,
                                                     approval_id=approval_id, user_id=USER)
        assert result["status"] == "SIMULATED_SUSPENSION"

        file_path = tmp_path / "sample.bin"
        file_path.write_bytes(b"test")
        approval_id = _approval("FILE_QUARANTINE", str(file_path),
                                {"source_path": str(file_path), "reason": "test"})
        result = offence.quarantine_file(db, str(file_path), "test", approval_id=approval_id, user_id=USER)
        assert result["success"]
        assert not file_path.exists()
    finally:
        db.close()


def test_quarantine_audit_failure_restores_source_and_does_not_commit_approval(tmp_path, monkeypatch):
    offence = OffenceAI()
    source = tmp_path / "rollback.bin"
    source.write_bytes(b"original")
    approval_id = _approval("FILE_QUARANTINE", str(source),
                            {"source_path": str(source), "reason": "audit failure"})
    monkeypatch.setattr(AuditChainService, "record_event", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError()))
    db = SessionLocal()
    try:
        result = offence.quarantine_file(db, str(source), "audit failure", approval_id=approval_id, user_id=USER)
        assert "error" in result
        assert source.read_bytes() == b"original"
    finally:
        db.close()


def test_approval_storage_failure_denies_consumption(monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError
    approval_id = _approval("EMERGENCY_RESET", None, {})
    db = SessionLocal()
    monkeypatch.setattr(service, "_write_lock", lambda _db: (_ for _ in ()).throw(SQLAlchemyError()))
    try:
        with pytest.raises(ApprovalError, match="storage is unavailable"):
            service.consume(db, approval_id=approval_id, user_id=USER, action="EMERGENCY_RESET",
                            target=None, payload={})
    finally:
        db.close()


def test_defence_escrow_restore_internal_call_requires_approval():
    from app.agents.defence import DefenceAI
    db = SessionLocal()
    try:
        with pytest.raises(ApprovalError):
            DefenceAI().restore_escrow_backup("key", "token", db=db)
    finally:
        db.close()


def test_defence_vault_unlock_decrypt_and_escrow_generation_require_approval():
    from app.agents.defence import DefenceAI
    defence = DefenceAI()
    db = SessionLocal()
    try:
        assert defence.unlock_vault("passphrase", db)["pending_approval"]
        assert defence.decrypt_secret(db, 999999, "passphrase").get("error") == "Vault item not found"
        assert "error" in defence.generate_escrow_backup("recovery data", db=db)
    finally:
        db.close()


def test_defence_vault_unlock_decrypt_and_escrow_generation_require_approval():
    from app.agents.defence import DefenceAI
    defence = DefenceAI()
    db = SessionLocal()
    try:
        assert defence.unlock_vault("passphrase", db)["pending_approval"]
        assert defence.decrypt_secret(db, 999999, "passphrase").get("error") == "Vault item not found"
        assert "error" in defence.generate_escrow_backup("recovery data", db=db)
    finally:
        db.close()


def test_boolean_permission_api_cannot_authorize_high_impact_actions():
    from app.core.permissions import AgentRole, Permission, check_permission
    with pytest.raises(TypeError):
        check_permission(AgentRole.OFFENCE, Permission.ACTIVATE_EMERGENCY, True)
    permitted, _ = check_permission(AgentRole.OFFENCE, Permission.ACTIVATE_EMERGENCY)
    assert not permitted
