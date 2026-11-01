"""
Cryptographic Maze Vault API Router.
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.agents.controller import controller_ai
from app.database import VaultItem, get_db
from app.security.auth import require_permission

router = APIRouter(prefix="/vault", tags=["Vault"])


class UnlockVaultRequest(BaseModel):
    passphrase: str


class StoreVaultItemRequest(BaseModel):
    label: str
    plaintext: str
    passphrase: str
    category: str = "CREDENTIAL"


class DecryptVaultItemRequest(BaseModel):
    passphrase: str


class EscrowRequest(BaseModel):
    payload: str


class RestoreEscrowRequest(BaseModel):
    recovery_key: str
    encrypted_token: str


@router.get("/status")
def get_vault_status(db: Session = Depends(get_db), _user=Depends(require_permission("vault:read"))):
    """Returns lock state, item count, and cryptographic cipher standards."""
    item_count = db.query(VaultItem).count()
    return {
        "is_locked": controller_ai.defence.is_vault_locked,
        "items_count": item_count,
        "algorithm": "AES-256-GCM + PBKDF2-HMAC-SHA256 (600,000 rounds) + HKDF Layering",
        "recovery_mechanism": "Fernet Escrow Enveloping"
    }


@router.post("/lock")
def lock_vault(_user=Depends(require_permission("vault:write"))):
    """Immediately locks the cryptographic vault and clears active session memory keys."""
    controller_ai.defence.lock_vault(reason="User invoked vault lock")
    return {"status": "LOCKED", "message": "Cryptographic Vault successfully sealed."}


@router.post("/unlock")
def unlock_vault(req: UnlockVaultRequest, db: Session = Depends(get_db), _user=Depends(require_permission("vault:write"))):
    """Verifies passphrase and unlocks vault session."""
    if not req.passphrase:
        raise HTTPException(status_code=400, detail="Passphrase cannot be empty")
    result = controller_ai.defence.unlock_vault(req.passphrase, db)
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["message"])
    return result


@router.get("/items")
def list_vault_items(db: Session = Depends(get_db), _user=Depends(require_permission("vault:read"))):
    """Lists metadata for all stored encrypted items (does not reveal plaintexts)."""
    items = db.query(VaultItem).order_by(VaultItem.id.desc()).all()
    return {
        "items": [
            {
                "id": it.id,
                "label": it.label,
                "category": it.category,
                "created_at": it.created_at.isoformat() if it.created_at else "",
                "is_locked": it.is_locked,
            }
            for it in items
        ]
    }


@router.post("/items")
def store_vault_item(req: StoreVaultItemRequest, db: Session = Depends(get_db), _user=Depends(require_permission("vault:write"))):
    """Encrypts plaintext with Cryptographic Maze layered AEAD encryption and stores in vault."""
    if not req.label or not req.plaintext or not req.passphrase:
        raise HTTPException(status_code=400, detail="Label, plaintext, and passphrase are required.")
    return controller_ai.defence.encrypt_and_store_secret(
        db=db,
        label=req.label,
        plaintext=req.plaintext,
        passphrase=req.passphrase,
        category=req.category
    )


@router.post("/items/{item_id}/decrypt")
def decrypt_vault_item(item_id: int, req: DecryptVaultItemRequest, db: Session = Depends(get_db), _user=Depends(require_permission("vault:write"))):
    """Decrypts a vault item after verifying authentication tag and passphrase."""
    res = controller_ai.defence.decrypt_secret(db=db, item_id=item_id, passphrase=req.passphrase)
    if "error" in res:
        raise HTTPException(status_code=401, detail=res["error"])
    return res


@router.post("/escrow")
def generate_escrow_backup(req: EscrowRequest, _user=Depends(require_permission("vault:write"))):
    """Generates an offline emergency recovery token for disaster recovery."""
    if not req.payload:
        raise HTTPException(status_code=400, detail="Payload cannot be empty.")
    return controller_ai.defence.generate_escrow_backup(req.payload)


@router.post("/escrow/restore")
def restore_escrow_backup(req: RestoreEscrowRequest, _user=Depends(require_permission("vault:write"))):
    """Restores a user-selected offline envelope without persisting or logging its key."""
    if not req.recovery_key or not req.encrypted_token:
        raise HTTPException(status_code=400, detail="Recovery key and encrypted token are required.")
    try:
        payload = controller_ai.defence.restore_escrow_backup(req.recovery_key, req.encrypted_token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Recovery failed: key or envelope is invalid.") from exc
    return {"restored": True, "payload": payload}
