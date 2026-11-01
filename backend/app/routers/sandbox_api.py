"""
Isolated Sandbox & Safe Browsing API Router.
"""
from typing import Any, Dict
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.services.sandbox_engine import sandbox_engine

router = APIRouter(prefix="/sandbox", tags=["Isolated Sandbox"])


class URLPreviewRequest(BaseModel):
    url: str


@router.post("/preview-url")
async def preview_url_safely(req: URLPreviewRequest):
    """
    Renders an untrusted URL in an isolated sandbox with scripts disabled
    and security headers verified.
    """
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return await sandbox_engine.inspect_url_safely(req.url)


@router.post("/preview-file")
async def preview_file_safely(file: UploadFile = File(...)):
    """
    Extracts raw bytecode and hex representations of an untrusted file without OS execution.
    """
    content = await file.read()
    filename = file.filename or "unknown.bin"
    return sandbox_engine.inspect_file_safely(filename, content)
