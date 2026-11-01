"""Optional, asynchronous, local-only Ethereum anchoring for audit hashes."""
import time
import threading
from urllib.parse import urlparse

from app.config import settings
from app.database import AuditEntry, BlockchainAnchor, SessionLocal

AUDIT_ABI = [
    {
        "type": "function", "name": "registerEventHash", "stateMutability": "nonpayable",
        "inputs": [{"name": "auditId", "type": "bytes32"}, {"name": "eventHash", "type": "bytes32"}],
        "outputs": [],
    },
    {
        "type": "function", "name": "verifyEventHash", "stateMutability": "view",
        "inputs": [{"name": "auditId", "type": "bytes32"}, {"name": "eventHash", "type": "bytes32"}],
        "outputs": [{"name": "matches", "type": "bool"}],
    },
    {
        "type": "function", "name": "getRecord", "stateMutability": "view",
        "inputs": [{"name": "auditId", "type": "bytes32"}],
        "outputs": [{"name": "eventHash", "type": "bytes32"}, {"name": "recordedAt", "type": "uint64"}, {"name": "exists", "type": "bool"}],
    },
    {
        "type": "event", "name": "AuditHashRegistered", "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "auditId", "type": "bytes32"},
            {"indexed": True, "name": "eventHash", "type": "bytes32"},
            {"indexed": False, "name": "recordedAt", "type": "uint64"},
        ],
    },
]

_anchor_lock = threading.Lock()


def _configuration():
    if not settings.BLOCKCHAIN_RPC_URL or not settings.BLOCKCHAIN_CONTRACT_ADDRESS:
        return None, "Local blockchain is not configured; audit verification remains local-only."
    parsed = urlparse(settings.BLOCKCHAIN_RPC_URL)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return None, "Only a loopback blockchain RPC endpoint is allowed in this prototype."
    try:
        from web3 import Web3
    except ImportError:
        return None, "Install backend requirements to enable the local blockchain adapter."
    if not Web3.is_address(settings.BLOCKCHAIN_CONTRACT_ADDRESS):
        return None, "Configured audit contract address is invalid."
    web3 = Web3(Web3.HTTPProvider(settings.BLOCKCHAIN_RPC_URL, request_kwargs={"timeout": 3}))
    if not web3.is_connected():
        return None, "Local blockchain node is unavailable; local hash-chain fallback is active."
    if web3.eth.chain_id not in {31337, 1337}:
        return None, "Blockchain adapter only permits the local Hardhat development chain."
    address = Web3.to_checksum_address(settings.BLOCKCHAIN_CONTRACT_ADDRESS)
    if not web3.eth.get_code(address):
        return None, "No audit contract is deployed at the configured local address."
    contract = web3.eth.contract(address=address, abi=AUDIT_ABI)
    return (web3, contract), None


def blockchain_status():
    configured, error = _configuration()
    if error:
        return {"available": False, "mode": "LOCAL_HASH_CHAIN", "message": error}
    web3, _ = configured
    return {"available": True, "mode": "LOCAL_HARDHAT", "chain_id": web3.eth.chain_id,
            "contract_address": settings.BLOCKCHAIN_CONTRACT_ADDRESS}


def anchor_audit_hash(audit_id: int, event_hash: str):
    configured, error = _configuration()
    if error:
        raise RuntimeError(error)
    web3, contract = configured
    if not web3.eth.accounts:
        raise RuntimeError("The local development node has no unlocked account for audit anchoring.")
    audit_key = web3.keccak(text=f"guard-ai-audit:{audit_id}")
    expected_hash = bytes.fromhex(event_hash)
    onchain_hash, _, exists = contract.functions.getRecord(audit_key).call()
    if exists:
        if onchain_hash != expected_hash:
            raise RuntimeError("The audit identifier is already anchored with a different hash.")
        logs = contract.events.AuditHashRegistered().get_logs(
            from_block=0, to_block="latest", argument_filters={"auditId": audit_key}
        )
        if not logs:
            raise RuntimeError("Existing on-chain record has no recoverable transaction reference.")
        tx_hash = logs[-1]["transactionHash"]
    else:
        tx_hash = contract.functions.registerEventHash(
            audit_key, expected_hash
        ).transact({"from": web3.eth.accounts[0]})
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=15)
        if receipt.status != 1:
            raise RuntimeError("The local blockchain transaction failed.")
    matches = contract.functions.verifyEventHash(audit_key, expected_hash).call()
    if not matches:
        raise RuntimeError("The local blockchain did not verify the stored audit hash.")
    return {"chain_id": web3.eth.chain_id, "transaction_hash": tx_hash.hex(),
            "contract_address": settings.BLOCKCHAIN_CONTRACT_ADDRESS}


def verify_audit_hash(audit_id: int, event_hash: str) -> bool:
    configured, error = _configuration()
    if error:
        raise RuntimeError(error)
    web3, contract = configured
    audit_key = web3.keccak(text=f"guard-ai-audit:{audit_id}")
    return bool(contract.functions.verifyEventHash(audit_key, bytes.fromhex(event_hash)).call())


def process_anchor(anchor_id: int, max_attempts: int = 3):
    """Retries pending anchoring away from request/defensive-operation paths."""
    with _anchor_lock:
        _process_anchor_locked(anchor_id, max_attempts)


def _process_anchor_locked(anchor_id: int, max_attempts: int):
    for attempt in range(max_attempts):
        db = SessionLocal()
        try:
            anchor = db.query(BlockchainAnchor).filter_by(id=anchor_id).first()
            if not anchor or anchor.status == "CONFIRMED":
                return
            entry = db.query(AuditEntry).filter_by(id=anchor.audit_entry_id).first()
            if not entry:
                anchor.status = "FAILED"
                anchor.last_error = "Local audit entry no longer exists; verification is required before retry."
                db.commit()
                return
            anchor.status = "PENDING"
            anchor.retry_count += 1
            db.commit()
            result = anchor_audit_hash(entry.id, entry.block_hash)
            anchor.chain_id = result["chain_id"]
            anchor.transaction_hash = result["transaction_hash"]
            anchor.contract_address = result["contract_address"]
            anchor.status = "CONFIRMED"
            anchor.last_error = None
            db.commit()
            return
        except Exception as exc:
            db.rollback()
            anchor = db.query(BlockchainAnchor).filter_by(id=anchor_id).first()
            if anchor:
                anchor.last_error = str(exc)[:500]
                anchor.status = "PENDING" if attempt < max_attempts - 1 else "FAILED"
                db.commit()
        finally:
            db.close()
        if attempt < max_attempts - 1:
            time.sleep(2 ** attempt)
