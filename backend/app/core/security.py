"""Security primitives, path sanitization, and cryptographic helpers."""
import base64
import hashlib
import os
import re
import secrets
from pathlib import Path
from typing import Optional

def generate_token(n_bytes: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_hex(n_bytes)

def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash string for byte stream."""
    return hashlib.sha256(data).hexdigest()

def compute_string_sha256(text: str) -> str:
    """Compute SHA-256 hash string for text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def sanitize_filepath(filename: str, base_dir: Path) -> Path:
    """
    Sanitize and resolve a filename inside base_dir to strictly prevent directory traversal attacks.
    """
    # Strip any directory components
    safe_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', Path(filename).name)
    if not safe_name:
        safe_name = f"quarantine_{secrets.token_hex(4)}.dat"
    resolved_path = (base_dir / safe_name).resolve()
    if not str(resolved_path).startswith(str(base_dir.resolve())):
        raise ValueError(f"Path traversal detected: {filename}")
    return resolved_path

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64_decode(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode("utf-8"))
