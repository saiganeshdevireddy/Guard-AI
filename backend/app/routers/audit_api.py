"""
Tamper-Evident Audit Ledger API Router.
"""
from typing import Any, Dict, List
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.audit_chain import AuditChainService
from app.database import AuditEntry, BlockchainAnchor, get_db
from app.services.blockchain_audit import blockchain_status, process_anchor
from app.security.auth import require_permission

router = APIRouter(prefix="/audit", tags=["Audit Ledger"])


@router.get("/entries")
def get_audit_entries(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db), _user=Depends(require_permission("audit:read"))):
    """Returns recent cryptographic hash blocks from the audit ledger."""
    entries = db.query(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit).all()
    integrity = AuditChainService.verify_integrity(db)
    anchors = {
        anchor.audit_entry_id: anchor
        for anchor in db.query(BlockchainAnchor).filter(
            BlockchainAnchor.audit_entry_id.in_([entry.id for entry in entries])
        ).all()
    } if entries else {}
    return {
        "entries": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "actor": e.actor,
                "payload_hash": e.payload_hash,
                "prev_hash": e.prev_hash,
                "block_hash": e.block_hash,
                "verified": integrity["valid"],
                "blockchain_anchor": ({
                    "status": anchors[e.id].status,
                    "chain_id": anchors[e.id].chain_id,
                    "transaction_hash": anchors[e.id].transaction_hash,
                    "contract_address": anchors[e.id].contract_address,
                    "retry_count": anchors[e.id].retry_count,
                    "last_error": anchors[e.id].last_error,
                } if e.id in anchors else None),
            }
            for e in entries
        ],
        "count": len(entries)
    }


@router.get("/verify")
def verify_audit_ledger_integrity(db: Session = Depends(get_db), _user=Depends(require_permission("audit:read"))):
    """
    Mathematically verifies the entire cryptographic chain from Genesis to tip.
    Detects any database modifications, deletions, or injected entries.
    """
    return AuditChainService.verify_integrity(db)


@router.get("/blockchain/status")
def get_blockchain_status(_user=Depends(require_permission("audit:read"))):
    """Reports actual local-chain connectivity; no demo transaction state is returned."""
    return blockchain_status()


@router.post("/entries/{entry_id}/anchor", status_code=status.HTTP_202_ACCEPTED)
def anchor_entry(entry_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db), _user=Depends(require_permission("audit:write"))):
    """Anchors only the SHA-256 entry hash on a configured local development chain."""
    integrity = AuditChainService.verify_integrity(db)
    if not integrity["valid"]:
        raise HTTPException(status_code=409, detail="Local audit chain failed integrity verification.")
    entry = db.query(AuditEntry).filter(AuditEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found.")
    existing = db.query(BlockchainAnchor).filter_by(audit_entry_id=entry_id).first()
    if existing and existing.status == "CONFIRMED":
        return {"status": existing.status, "chain_id": existing.chain_id,
                "transaction_hash": existing.transaction_hash,
                "message": "This audit hash is already confirmed on the local development chain."}
    if existing and existing.status == "PENDING":
        return {"status": existing.status, "message": "This audit hash already has an anchoring job in progress."}
    if existing:
        existing.status = "PENDING"
        existing.last_error = None
    else:
        existing = BlockchainAnchor(
            audit_entry_id=entry.id, contract_address="pending", status="PENDING", retry_count=0
        )
        db.add(existing)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(BlockchainAnchor).filter_by(audit_entry_id=entry_id).first()
        if existing:
            return {"status": existing.status, "message": "An anchoring job for this audit entry already exists."}
        raise HTTPException(status_code=409, detail="Could not create a unique anchoring job.")
    db.refresh(existing)
    background_tasks.add_task(process_anchor, existing.id)
    return {"status": "PENDING", "message": "Local-chain anchoring queued. Poll the audit list for confirmation."}


@router.get("/entries/{entry_id}/verify-blockchain")
def verify_entry_on_blockchain(entry_id: int, db: Session = Depends(get_db), _user=Depends(require_permission("audit:read"))):
    """Compares an anchored hash with the current database entry hash."""
    entry = db.query(AuditEntry).filter_by(id=entry_id).first()
    anchor = db.query(BlockchainAnchor).filter_by(audit_entry_id=entry_id).first()
    if not entry or not anchor:
        raise HTTPException(status_code=404, detail="No anchored audit entry was found.")
    if not AuditChainService.verify_integrity(db)["valid"]:
        raise HTTPException(status_code=409, detail="Local audit chain integrity verification failed.")
    if anchor.status != "CONFIRMED":
        return {"status": anchor.status, "verified": False, "message": "No confirmed on-chain record is available."}
    try:
        from app.services.blockchain_audit import verify_audit_hash
        verified = verify_audit_hash(entry.id, entry.block_hash)
    except Exception:
        verified = False
    return {"status": "CONFIRMED", "verified": verified,
            "message": "On-chain hash matches the current local entry." if verified else "On-chain and local hashes do not match, or the local chain is unavailable."}
