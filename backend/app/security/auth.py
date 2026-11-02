"""Password login and revocable short-lived JWT bearer authentication.

Passwords are hashed with Argon2id through pwdlib. JWT encoding and all token
validation are provided by PyJWT. This module never logs credentials or tokens.
"""
import getpass
import json
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.database import RevokedToken, get_db

bearer_scheme = HTTPBearer(auto_error=False)
password_hasher = PasswordHash.recommended()
_dummy_password_hash = password_hasher.hash(secrets.token_urlsafe(32))

ROLE_PERMISSIONS = {
    "admin": {"*"},
    "operator": {
        "agents:read", "agents:write", "scanner:read", "scanner:write",
        "vault:read", "vault:write", "audit:read", "audit:write",
        "emergency:read", "emergency:write", "sandbox:write",
        "android:read", "android:write",
    },
    "analyst": {"agents:read", "scanner:read", "scanner:write", "audit:read"},
    "viewer": {"agents:read", "scanner:read", "audit:read"},
}


def hash_password(password: str) -> str:
    """Create a pwdlib recommended Argon2id hash for out-of-band provisioning."""
    if not password:
        raise ValueError("Password cannot be empty.")
    return password_hasher.hash(password)


def _users() -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(settings.AUTH_USERS_JSON)
    except (TypeError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, list):
        return {}
    users = {}
    for user in raw:
        if not isinstance(user, dict):
            continue
        username, password_hash, role = user.get("username"), user.get("password_hash"), user.get("role")
        if (isinstance(username, str) and username and isinstance(password_hash, str)
                and password_hash.startswith("$argon2id$") and isinstance(role, str)
                and role in ROLE_PERMISSIONS and user.get("active") is True):
            users[username] = {"password_hash": password_hash, "role": role}
    return users


def auth_is_configured() -> bool:
    secret = settings.AUTH_TOKEN_SECRET.encode("utf-8")
    return len(secret) >= 32 and bool(_users()) and 60 <= settings.AUTH_TOKEN_TTL_SECONDS <= 3600


def _require_auth_configuration() -> None:
    if not auth_is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured. Set a strong signing secret and at least one active Argon2id user.",
        )


class TokenRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


def issue_access_token(username: str, *, now: int | None = None, expires_in: int | None = None) -> str:
    """Issue a standard HS256 JWT; optional time parameters support expiry tests."""
    _require_auth_configuration()
    if username not in _users():
        raise ValueError("Unknown or inactive user.")
    issued_at = int(time.time() if now is None else now)
    lifetime = settings.AUTH_TOKEN_TTL_SECONDS if expires_in is None else expires_in
    payload = {
        "iss": "guard-ai", "sub": username, "iat": issued_at,
        "exp": issued_at + lifetime, "jti": secrets.token_urlsafe(24),
    }
    return jwt.encode(payload, settings.AUTH_TOKEN_SECRET, algorithm="HS256", headers={"typ": "JWT"})


def authenticate_password(username: str, password: str) -> str | None:
    _require_auth_configuration()
    user = _users().get(username)
    candidate_hash = user["password_hash"] if user else _dummy_password_hash
    try:
        valid = password_hasher.verify(password, candidate_hash)
    except Exception:
        valid = False
    return username if valid and user else None


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _require_auth_configuration()
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer access token required.", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.AUTH_TOKEN_SECRET,
            algorithms=["HS256"],
            issuer="guard-ai",
            options={"require": ["iss", "sub", "iat", "exp", "jti"]},
        )
        if payload["exp"] - payload["iat"] > 3600:
            raise jwt.InvalidTokenError("Token lifetime exceeds policy")
        user = _users().get(payload["sub"])
        if user is None:
            raise jwt.InvalidTokenError("User is inactive or unknown")
        try:
            revoked = db.query(RevokedToken).filter_by(jti=payload["jti"]).first()
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(status_code=503, detail="Authentication storage is unavailable; request denied.") from None
        if revoked:
            raise jwt.InvalidTokenError("Token has been revoked")
        return {"username": payload["sub"], "role": user["role"], "jti": payload["jti"], "exp": payload["exp"]}
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Access token is invalid, expired, or revoked.", headers={"WWW-Authenticate": "Bearer"}) from None


def require_permission(permission: str):
    def dependency(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        permissions = ROLE_PERMISSIONS[user["role"]]
        if "*" not in permissions and permission not in permissions:
            raise HTTPException(status_code=403, detail="This account does not have permission for this operation.")
        return user
    return dependency


def revoke_access_token(user: dict[str, Any], db: Session) -> None:
    expires_at = datetime.fromtimestamp(user["exp"], tz=timezone.utc)
    try:
        if not db.query(RevokedToken).filter_by(jti=user["jti"]).first():
            db.add(RevokedToken(jti=user["jti"], expires_at=expires_at))
            db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=503, detail="Authentication storage is unavailable; token could not be revoked.") from None


def _provision_user() -> None:
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords did not match.")
    role = input("Role (admin/operator/analyst/viewer): ").strip().lower()
    if role not in ROLE_PERMISSIONS:
        raise SystemExit("Unsupported role.")
    print(json.dumps({
        "username": username, "password_hash": hash_password(password),
        "role": role, "active": True,
    }, separators=(",", ":")))


if __name__ == "__main__" and "--provision-user" in sys.argv:
    _provision_user()
