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
    DATABASE_URL: str = f"sqlite:///{DATA_DIR / 'guard_ai.db'}"
    
    # Security & Cryptography
    SECRET_KEY: str = os.getenv("GUARD_AI_SECRET_KEY", "guard-ai-secure-master-secret-key-32b!")
    VAULT_ITERATIONS: int = 600000  # OWASP recommended minimum for PBKDF2
    
    # Privacy & Hybrid AI Mode
    LOCAL_ONLY_MODE: bool = True  # Strict privacy: do not transmit sensitive data to cloud
    CLOUD_AI_PROVIDER: str = "fallback"  # Options: 'fallback', 'gemini', 'openai'
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # Agent Communication & Polling
    AGENT_HEARTBEAT_INTERVAL_SEC: int = 5
    EMERGENCY_LOCKDOWN_ENABLED: bool = False
    
    # Cross-platform endpoints
    ANDROID_COMPANION_ENABLED: bool = True

settings = Settings()
