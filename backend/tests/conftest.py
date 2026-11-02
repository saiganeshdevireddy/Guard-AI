"""Test configuration installed before any application module is imported."""
import hashlib
import json
import os
import secrets
import sys
import tempfile
import shutil
import pytest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = BACKEND_ROOT / "data" / "guard_ai.db"
_default_database_digest = hashlib.sha256(DEFAULT_DATABASE.read_bytes()).hexdigest() if DEFAULT_DATABASE.exists() else None

# Every pytest process gets its own database. This is set before tests import app.main.
_test_data_dir = Path(tempfile.mkdtemp(prefix="guard-ai-pytest-"))
os.environ["GUARD_AI_DATABASE_URL"] = f"sqlite:///{(_test_data_dir / 'pytest.sqlite3').as_posix()}"
os.environ["GUARD_AI_AUTH_TOKEN_SECRET"] = secrets.token_urlsafe(48)
os.environ["GUARD_AI_AUTH_TOKEN_TTL_SECONDS"] = "900"
os.environ["GUARD_AI_AUTH_USERS"] = "[]"

sys.path.insert(0, str(BACKEND_ROOT))

# The only test identities are generated for this pytest process and cannot be reused.
from app.config import settings
from app.security.auth import hash_password

TEST_ADMIN_USERNAME = "pytest-admin"
TEST_ADMIN_PASSWORD = secrets.token_urlsafe(32)
TEST_ANALYST_USERNAME = "pytest-analyst"
TEST_ANALYST_PASSWORD = secrets.token_urlsafe(32)
settings.AUTH_USERS_JSON = json.dumps([
    {"username": TEST_ADMIN_USERNAME, "password_hash": hash_password(TEST_ADMIN_PASSWORD), "role": "admin", "active": True},
    {"username": TEST_ANALYST_USERNAME, "password_hash": hash_password(TEST_ANALYST_PASSWORD), "role": "analyst", "active": True},
])


@pytest.fixture
def test_auth_users():
    return {
        "admin_username": TEST_ADMIN_USERNAME,
        "admin_password": TEST_ADMIN_PASSWORD,
        "analyst_username": TEST_ANALYST_USERNAME,
        "analyst_password": TEST_ANALYST_PASSWORD,
    }


def _default_database_unchanged() -> bool:
    if _default_database_digest is None:
        return not DEFAULT_DATABASE.exists()
    return DEFAULT_DATABASE.exists() and hashlib.sha256(DEFAULT_DATABASE.read_bytes()).hexdigest() == _default_database_digest


@pytest.fixture
def default_database_unchanged():
    return _default_database_unchanged


def pytest_sessionfinish(session, exitstatus):
    from app.database import engine
    engine.dispose()
    if not _default_database_unchanged():
        print("ERROR: pytest modified the default application database.", file=sys.stderr)
        session.exitstatus = 1
    shutil.rmtree(_test_data_dir, ignore_errors=True)
