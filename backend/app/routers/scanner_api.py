"""
Threat Scanner and Discovery API Router.
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from urllib.parse import urlsplit

from app.agents.controller import controller_ai
from app.config import settings
from app.database import ThreatEvent, get_db
from app.services.hybrid_ai import hybrid_ai
from app.security.auth import require_permission

router = APIRouter(prefix="/scan", tags=["Scanner"])


class URLScanRequest(BaseModel):
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


class TextScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)


class NetworkScanRequest(BaseModel):
    ssid: str = Field(min_length=1, max_length=128)
    security_type: str = Field(default="OPEN", max_length=32)
    bssid: str = Field(default="00:00:00:00:00:00", max_length=64)
    dns_servers: List[str] = Field(default_factory=list, max_length=8)
    captive_portal: bool = False
    duplicate_ssids_detected: int = Field(default=1, ge=1, le=100)


@router.post("/url")
def scan_url(req: URLScanRequest, db: Session = Depends(get_db), _user=Depends(require_permission("scanner:write"))):
    """Runs target URL through Finder AI, evaluates phishing, and checks security headers."""
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    report = controller_ai.finder.scan_url(req.url)
    # Generate hybrid explanation
    explanation = hybrid_ai.analyze_threat_context(
        indicator=req.url,
        category="URL",
        severity=report["severity"],
        raw_details=report
    )
    return {
        "report": report,
        "hybrid_explanation": explanation
    }


@router.post("/file")
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db), _user=Depends(require_permission("scanner:write"))):
    """Uploads and conducts static bytecode inspection, entropy, and malicious signature heuristics."""
    content = await file.read(settings.MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {settings.MAX_UPLOAD_BYTES // (1024 * 1024)} MB inspection limit.")
    filename = file.filename or "unknown.bin"
    report = controller_ai.finder.scan_file_bytes(content, filename)
    explanation = hybrid_ai.analyze_threat_context(
        indicator=filename,
        category="FILE",
        severity=report["severity"],
        raw_details=report
    )
    return {
        "report": report,
        "hybrid_explanation": explanation
    }


@router.post("/text")
def scan_text(req: TextScanRequest, db: Session = Depends(get_db), _user=Depends(require_permission("scanner:write"))):
    """Inspects text for urgent social engineering, financial fraud, and spam indicators."""
    report = controller_ai.finder.scan_text(req.text)
    explanation = hybrid_ai.analyze_threat_context(
        indicator=req.text[:40],
        category="SPAM",
        severity=report["severity"],
        raw_details=report
    )
    return {
        "report": report,
        "hybrid_explanation": explanation
    }


@router.post("/network")
def scan_network(req: NetworkScanRequest, db: Session = Depends(get_db), _user=Depends(require_permission("scanner:write"))):
    """Analyzes wireless network security posture, encryption protocols, and rogue AP flags."""
    network_data = req.dict()
    report = controller_ai.finder.scan_network(network_data)
    explanation = hybrid_ai.analyze_threat_context(
        indicator=req.ssid,
        category="NETWORK",
        severity=report["severity"],
        raw_details=report
    )
    return {
        "report": report,
        "hybrid_explanation": explanation
    }


@router.get("/threats")
def list_threat_events(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db), _user=Depends(require_permission("scanner:read"))):
    """Lists recent detected threat events stored in the database."""
    threats = db.query(ThreatEvent).order_by(ThreatEvent.id.desc()).limit(limit).all()
    return {
        "threats": [
            {
                "id": t.id,
                "timestamp": t.timestamp.isoformat(),
                "source_agent": t.source_agent,
                "severity": t.severity,
                "category": t.category,
                "indicator": t.indicator,
                "description": t.description,
                "details": t.details,
                "status": t.status,
            }
            for t in threats
        ],
        "count": len(threats)
    }
