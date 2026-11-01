"""
Tests for Cryptographic Maze Layered Security & AEAD Encryption.
"""
import pytest
from app.core.crypto_maze import CryptographicMazeEngine, crypto_maze


def test_encryption_and_decryption_success():
    """Verify that valid encryption and decryption round-trip succeeds."""
    engine = CryptographicMazeEngine(iterations=1000)
    plaintext = "CONFIDENTIAL_TOP_SECRET_CREDENTIAL_9942"
    passphrase = "MasterSecurePassword!2026"
    label = "BANK_API_KEY"

    encrypted = engine.encrypt_segmented(plaintext, passphrase, label=label)
    assert "ciphertext_b64" in encrypted
    assert "nonce_b64" in encrypted
    assert "salt_b64" in encrypted
    assert "tag_b64" in encrypted

    decrypted = engine.decrypt_segmented(encrypted, passphrase)
    assert decrypted == plaintext


def test_invalid_passphrase_rejection():
    """Verify that decryption fails and raises ValueError when wrong passphrase is provided."""
    engine = CryptographicMazeEngine(iterations=1000)
    plaintext = "SecretPayload"
    encrypted = engine.encrypt_segmented(plaintext, "CorrectPass123")

    with pytest.raises(ValueError) as excinfo:
        engine.decrypt_segmented(encrypted, "WrongPassword456")
    assert "Integrity verification failed" in str(excinfo.value) or "Decryption failed" in str(excinfo.value)


def test_tampered_ciphertext_detection():
    """Verify that tampering with any byte of ciphertext triggers AEAD authentication failure."""
    engine = CryptographicMazeEngine(iterations=1000)
    plaintext = "CriticalFinancialRecord"
    passphrase = "PasswordXYZ"
    encrypted = engine.encrypt_segmented(plaintext, passphrase)

    # Tamper with ciphertext by altering base64 characters
    tampered = dict(encrypted)
    raw_cipher = tampered["ciphertext_b64"]
    # Invert first character
    altered_char = "B" if raw_cipher[0] != "B" else "C"
    tampered["ciphertext_b64"] = altered_char + raw_cipher[1:]

    with pytest.raises(ValueError):
        engine.decrypt_segmented(tampered, passphrase)


def test_key_separation_isolation():
    """Verify that HKDF derives distinct, non-overlapping keys for each security layer."""
    engine = CryptographicMazeEngine(iterations=1000)
    root = engine.derive_root_key("TestPass", b"16_byte_salt_123")
    keys = engine.derive_segmented_keys(root)

    assert "header" in keys
    assert "payload" in keys
    assert "recovery" in keys
    assert keys["header"] != keys["payload"]
    assert keys["payload"] != keys["recovery"]
    assert len(keys["payload"]) == 32  # 256-bit key


def test_fernet_disaster_recovery_token():
    """Verify that offline disaster recovery envelope can restore encrypted secrets."""
    engine = CryptographicMazeEngine(iterations=1000)
    secret_note = "OFFLINE_VAULT_BACKUP_TOKEN_ALPHA"
    key, token = engine.generate_recovery_token(secret_note)

    assert isinstance(key, str)
    assert isinstance(token, str)

    restored = engine.restore_from_recovery_token(key, token)
    assert restored == secret_note
