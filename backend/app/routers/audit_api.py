"""
Tamper-Evident Audit Ledger API Router.
"""
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.audit_chain import AuditChainService
from app.database import AuditEntry, get_db

router = APIRouter(prefix="/audit", tags=["Audit Ledger"])


@router.get("/entries")
def get_audit_entries(limit: int = 50, db: Session = Depends(get_db)):
    """Returns recent cryptographic hash blocks from the audit ledger."""
    entries = db.query(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit).all()
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
                "verified": e.verified,
            }
            for e in entries
        ],
        "count": len(entries)
    }


@router.get("/verify")
def verify_audit_ledger_integrity(db: Session = Depends(get_db)):
    """
    Mathematically verifies the entire cryptographic chain from Genesis to tip.
    Detects any database modifications, deletions, or injected entries.
    """
    return AuditChainService.verify_integrity(db)
