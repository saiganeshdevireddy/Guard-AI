"""
Isolated Sandbox & Safe Browsing API Router.
"""
from typing import Any, Dict
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlsplit

from app.services.sandbox_engine import sandbox_engine
from app.config import settings
from app.security.auth import require_permission

router = APIRouter(prefix="/sandbox", tags=["Isolated Sandbox"])


class URLPreviewRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        candidate = value if "://" in value else f"https://{value}"
        try:
            parsed = urlsplit(candidate)
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Enter a valid HTTP or HTTPS URL") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Enter a valid HTTP or HTTPS URL without embedded credentials")
        return value


@router.post("/preview-url")
async def preview_url_safely(req: URLPreviewRequest, _user=Depends(require_permission("sandbox:write"))):
    """Reviews a URL locally; remote fetching and rendering are intentionally disabled."""
    return await sandbox_engine.inspect_url_safely(req.url)


@router.post("/preview-file")
async def preview_file_safely(file: UploadFile = File(...), _user=Depends(require_permission("sandbox:write"))):
    """
    Extracts raw bytecode and hex representations of an untrusted file without OS execution.
    """
    content = await file.read(settings.MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {settings.MAX_UPLOAD_BYTES // (1024 * 1024)} MB inspection limit.")
    filename = file.filename or "unknown.bin"
    return sandbox_engine.inspect_file_safely(filename, content)
