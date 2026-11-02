"""
Tamper-Evident Audit Ledger (Cryptographic Hash-Chaining).

Provides mathematical proof of event order and immutability:
- Each event entry includes the SHA-256 hash of the previous entry.
- Modifying a retained record or deleting an interior record invalidates the chain.
- Removing a trailing suffix cannot be detected without an externally stored checkpoint.
- Contains only hashed representations of sensitive details to preserve privacy.
"""
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from app.database import AuditEntry

GENESIS_HASH = "0" * 64


class AuditChainService:
    """Manages appending and verifying tamper-evident audit blocks."""

    @staticmethod
    def _calculate_block_hash(
        prev_hash: str,
        timestamp_str: str,
        actor: str,
        event_type: str,
        payload_hash: str
    ) -> str:
        """Computes deterministic SHA-256 block hash."""
        raw_material = f"{prev_hash}|{timestamp_str}|{actor}|{event_type}|{payload_hash}"
        return hashlib.sha256(raw_material.encode("utf-8")).hexdigest()

    @classmethod
    def record_event(
        cls,
        db: Session,
        actor: str,
        event_type: str,
        payload: Dict[str, Any]
    ) -> AuditEntry:
        """
        Appends an event to the cryptographic audit chain.
        """
        # 1. Compute payload hash (privacy: does not store plaintext)
        payload_json = json.dumps(payload, sort_keys=True)
        payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

        # 2. Retrieve the most recent block's hash
        last_entry = db.query(AuditEntry).order_by(AuditEntry.id.desc()).first()
        prev_hash = last_entry.block_hash if last_entry else GENESIS_HASH

        # 3. Create timestamp and compute new block hash
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()
        block_hash = cls._calculate_block_hash(
            prev_hash=prev_hash,
            timestamp_str=timestamp_str,
            actor=actor,
            event_type=event_type,
            payload_hash=payload_hash,
        )

        entry = AuditEntry(
            timestamp=now,
            timestamp_str=timestamp_str,
            event_type=event_type,
            actor=actor,
            payload_hash=payload_hash,
            prev_hash=prev_hash,
            block_hash=block_hash,
            verified=True,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry

    @classmethod
    def verify_integrity(cls, db: Session) -> Dict[str, Any]:
        """
        Validates the entire chain from Genesis to current tip.
        Returns validation status, total block count, and compromised block id if tampered.
        """
        entries = db.query(AuditEntry).order_by(AuditEntry.id.asc()).all()
        if not entries:
            return {
                "valid": True,
                "block_count": 0,
                "message": "Chain is empty (no entries recorded yet).",
                "compromised_id": None,
            }

        expected_prev = GENESIS_HASH
        for idx, entry in enumerate(entries):
            # Check 1: Previous hash link
            if entry.prev_hash != expected_prev:
                return {
                    "valid": False,
                    "block_count": len(entries),
                    "message": f"Broken chain link detected at block #{entry.id}. Expected {expected_prev[:12]}..., found {entry.prev_hash[:12]}...",
                    "compromised_id": entry.id,
                }

            # Check 2: Re-calculate hash
            t_str = entry.timestamp_str or entry.timestamp.isoformat()
            recomputed = cls._calculate_block_hash(
                prev_hash=entry.prev_hash,
                timestamp_str=t_str,
                actor=entry.actor,
                event_type=entry.event_type,
                payload_hash=entry.payload_hash,
            )
            if recomputed != entry.block_hash:
                return {
                    "valid": False,
                    "block_count": len(entries),
                    "message": f"Hash integrity failure at block #{entry.id}. Content modified or tampered.",
                    "compromised_id": entry.id,
                }

            expected_prev = entry.block_hash

        return {
            "valid": True,
            "block_count": len(entries),
            "message": "Cryptographic chain verified. All blocks authentic and unmodified.",
            "compromised_id": None,
            "latest_block_hash": expected_prev,
        }
