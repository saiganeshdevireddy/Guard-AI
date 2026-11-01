"""Configuration settings for Guard AI."""
import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_DIR = DATA_DIR / "sandbox"
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseModel):
    PROJECT_NAME: str = "Guard AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = os.getenv("GUARD_AI_DATABASE_URL", f"sqlite:///{DATA_DIR / 'guard_ai.db'}")
    
    # Security & Cryptography
    VAULT_ITERATIONS: int = 600000  # OWASP recommended minimum for PBKDF2
    
    # Privacy & Hybrid AI Mode
    LOCAL_ONLY_MODE: bool = True  # Cloud inference is not implemented in this prototype.

    # HTTP and upload boundaries
    CORS_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv(
            "GUARD_AI_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
        ).split(",")
        if origin.strip()
    ]
    MAX_UPLOAD_BYTES: int = int(os.getenv("GUARD_AI_MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))

    # Optional local Hardhat audit anchoring. Never configured by default.
    BLOCKCHAIN_RPC_URL: str = os.getenv("GUARD_AI_BLOCKCHAIN_RPC_URL", "")
    BLOCKCHAIN_CONTRACT_ADDRESS: str = os.getenv("GUARD_AI_BLOCKCHAIN_CONTRACT_ADDRESS", "")

    # Authentication is fail-closed: no default token secret or demo user.
    AUTH_TOKEN_SECRET: str = os.getenv("GUARD_AI_AUTH_TOKEN_SECRET", "")
    AUTH_TOKEN_TTL_SECONDS: int = int(os.getenv("GUARD_AI_AUTH_TOKEN_TTL_SECONDS", "900"))
    AUTH_USERS_JSON: str = os.getenv("GUARD_AI_AUTH_USERS", "[]")

    # Worker communication is disabled unless an operator supplies a trusted CA
    # and a separate ticket-signing key through the process environment.
    WORKER_CA_CERT_PEM: str = os.getenv("GUARD_AI_WORKER_CA_CERT_PEM", "")
    WORKER_CRL_PEM: str = os.getenv("GUARD_AI_WORKER_CRL_PEM", "")
    WORKER_TICKET_SIGNING_KEY: str = os.getenv("GUARD_AI_WORKER_TICKET_SIGNING_KEY", "")
    WORKER_TICKET_SIGNING_KEY_ID: str = os.getenv("GUARD_AI_WORKER_TICKET_SIGNING_KEY_ID", "v1")
    WORKER_TICKET_VERIFY_KEYS_JSON: str = os.getenv("GUARD_AI_WORKER_TICKET_VERIFY_KEYS_JSON", "{}")
    
    # Agent Communication & Polling
    AGENT_HEARTBEAT_INTERVAL_SEC: int = 5
    EMERGENCY_LOCKDOWN_ENABLED: bool = False
    
    # Cross-platform endpoints
    ANDROID_COMPANION_ENABLED: bool = True

settings = Settings()
