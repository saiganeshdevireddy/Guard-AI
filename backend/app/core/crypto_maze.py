"""
Cryptographic Maze Security: Layered Authenticated Encryption & Key Management.

Adheres strictly to established cryptographic standards:
1. AES-256-GCM Authenticated Encryption with Associated Data (AEAD).
2. OWASP-compliant PBKDF2-HMAC-SHA256 key derivation (600,000 rounds).
3. HKDF (RFC 5869) key separation for segmented data isolation (Header vs Body vs Recovery).
4. Fernet dual-envelope fallback for secure disaster recovery.
"""
import base64
import json
import os
import secrets
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings
from app.core.security import b64_decode, b64_encode


class CryptographicMazeEngine:
    """
    Layered security engine providing multi-stage key derivation,
    data segmentation, and tamper-evident authenticated encryption.
    """

    def __init__(self, iterations: int = settings.VAULT_ITERATIONS):
        self.iterations = iterations

    def derive_root_key(self, passphrase: str, salt: bytes) -> bytes:
        """
        Derives a 256-bit root key from a user passphrase using PBKDF2-HMAC-SHA256.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    def derive_segmented_keys(self, root_key: bytes) -> Dict[str, bytes]:
        """
        Derives compartmentalized, separated keys for different security layers via HKDF:
        - 'header': for metadata & access control tags
        - 'payload': for confidential primary content
        - 'recovery': for emergency escrow recovery
        """
        def hkdf_sub(info_label: bytes) -> bytes:
            return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=info_label,
            ).derive(root_key)

        return {
            "header": hkdf_sub(b"guard-ai-crypto-maze-header-layer"),
            "payload": hkdf_sub(b"guard-ai-crypto-maze-payload-layer"),
            "recovery": hkdf_sub(b"guard-ai-crypto-maze-recovery-layer"),
        }

    def encrypt_segmented(
        self,
        plaintext: str,
        passphrase: str,
        label: str = "DEFAULT",
        associated_data: str = "GUARD_AI_SECURE_ENCLAVE"
    ) -> Dict[str, str]:
        """
        Encrypts plaintext with AES-256-GCM using multi-tier key separation.
        Returns base64 components: salt, nonce, ciphertext, and tag.
        """
        salt = os.urandom(16)
        nonce = os.urandom(12)  # Recommended 96-bit nonce for AES-GCM
        root_key = self.derive_root_key(passphrase, salt)
        subkeys = self.derive_segmented_keys(root_key)

        aesgcm = AESGCM(subkeys["payload"])
        aad_bytes = f"{label}:{associated_data}".encode("utf-8")
        
        # In cryptography library, aesgcm.encrypt appends 16-byte tag to the ciphertext
        encrypted_raw = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad_bytes)
        
        ciphertext = encrypted_raw[:-16]
        tag = encrypted_raw[-16:]

        return {
            "salt_b64": b64_encode(salt),
            "nonce_b64": b64_encode(nonce),
            "ciphertext_b64": b64_encode(ciphertext),
            "tag_b64": b64_encode(tag),
            "label": label,
        }

    def decrypt_segmented(
        self,
        encrypted_dict: Dict[str, str],
        passphrase: str,
        associated_data: str = "GUARD_AI_SECURE_ENCLAVE"
    ) -> str:
        """
        Decrypts and cryptographically verifies ciphertext integrity.
        Raises ValueError if authentication tag does not match (tampering detected).
        """
        try:
            salt = b64_decode(encrypted_dict["salt_b64"])
            nonce = b64_decode(encrypted_dict["nonce_b64"])
            ciphertext = b64_decode(encrypted_dict["ciphertext_b64"])
            tag = b64_decode(encrypted_dict["tag_b64"])
            label = encrypted_dict.get("label", "DEFAULT")

            root_key = self.derive_root_key(passphrase, salt)
            subkeys = self.derive_segmented_keys(root_key)

            aesgcm = AESGCM(subkeys["payload"])
            aad_bytes = f"{label}:{associated_data}".encode("utf-8")
            
            # Reconstruct combined ciphertext + tag for decryption
            combined = ciphertext + tag
            decrypted_bytes = aesgcm.decrypt(nonce, combined, aad_bytes)
            return decrypted_bytes.decode("utf-8")
        except InvalidTag:
            raise ValueError("Integrity verification failed: Invalid passphrase or corrupted/tampered ciphertext.")
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def generate_recovery_token(self, payload: str) -> Tuple[str, str]:
        """
        Generates a Fernet emergency envelope for offline paper/secure backup recovery.
        Returns (recovery_key, encrypted_token).
        """
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(payload.encode("utf-8")).decode("utf-8")
        return key.decode("utf-8"), token

    def restore_from_recovery_token(self, recovery_key: str, token: str) -> str:
        """Restores payload using emergency recovery key."""
        try:
            f = Fernet(recovery_key.encode("utf-8"))
            return f.decrypt(token.encode("utf-8")).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Recovery token restoration failed: {str(e)}")


crypto_maze = CryptographicMazeEngine()
