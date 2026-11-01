"""
Cryptographic Maze Vault API Router.
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.agents.controller import controller_ai
from app.database import VaultItem, get_db

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


@router.get("/status")
def get_vault_status(db: Session = Depends(get_db)):
    """Returns lock state, item count, and cryptographic cipher standards."""
    item_count = db.query(VaultItem).count()
    return {
        "is_locked": controller_ai.defence.is_vault_locked,
        "items_count": item_count,
        "algorithm": "AES-256-GCM + PBKDF2-HMAC-SHA256 (600,000 rounds) + HKDF Layering",
        "recovery_mechanism": "Fernet Escrow Enveloping"
    }


@router.post("/lock")
def lock_vault():
    """Immediately locks the cryptographic vault and clears active session memory keys."""
    controller_ai.defence.lock_vault(reason="User invoked vault lock")
    return {"status": "LOCKED", "message": "Cryptographic Vault successfully sealed."}


@router.post("/unlock")
def unlock_vault(req: UnlockVaultRequest, db: Session = Depends(get_db)):
    """Verifies passphrase and unlocks vault session."""
    if not req.passphrase:
        raise HTTPException(status_code=400, detail="Passphrase cannot be empty")
    result = controller_ai.defence.unlock_vault(req.passphrase, db)
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["message"])
    return result


@router.get("/items")
def list_vault_items(db: Session = Depends(get_db)):
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
def store_vault_item(req: StoreVaultItemRequest, db: Session = Depends(get_db)):
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
def decrypt_vault_item(item_id: int, req: DecryptVaultItemRequest, db: Session = Depends(get_db)):
    """Decrypts a vault item after verifying authentication tag and passphrase."""
    res = controller_ai.defence.decrypt_secret(db=db, item_id=item_id, passphrase=req.passphrase)
    if "error" in res:
        raise HTTPException(status_code=401, detail=res["error"])
    return res


@router.post("/escrow")
def generate_escrow_backup(req: EscrowRequest):
    """Generates an offline emergency recovery token for disaster recovery."""
    if not req.payload:
        raise HTTPException(status_code=400, detail="Payload cannot be empty.")
    return controller_ai.defence.generate_escrow_backup(req.payload)
