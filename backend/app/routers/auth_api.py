"""Credential exchange for configured Guard AI API users."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.security.auth import TokenRequest, authenticate_password, get_current_user, issue_access_token, revoke_access_token

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/token")
def create_token(request: TokenRequest):
    username = authenticate_password(request.username, request.password)
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password.",
                            headers={"WWW-Authenticate": "Bearer"})
    return {
        "access_token": issue_access_token(username),
        "token_type": "bearer",
        "expires_in": settings.AUTH_TOKEN_TTL_SECONDS,
    }


@router.post("/revoke")
def revoke_token(user=Depends(get_current_user), db: Session = Depends(get_db)):
    revoke_access_token(user, db)
    return {"revoked": True}
