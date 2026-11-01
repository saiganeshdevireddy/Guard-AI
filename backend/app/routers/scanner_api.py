"""
Threat Scanner and Discovery API Router.
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.agents.controller import controller_ai
from app.database import ThreatEvent, get_db
from app.services.hybrid_ai import hybrid_ai

router = APIRouter(prefix="/scan", tags=["Scanner"])


class URLScanRequest(BaseModel):
    url: str


class TextScanRequest(BaseModel):
    text: str


class NetworkScanRequest(BaseModel):
    ssid: str
    security_type: str = "OPEN"
    bssid: str = "00:00:00:00:00:00"
    dns_servers: List[str] = []
    captive_portal: bool = False
    duplicate_ssids_detected: int = 1


@router.post("/url")
def scan_url(req: URLScanRequest, db: Session = Depends(get_db)):
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
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Uploads and conducts static bytecode inspection, entropy, and malicious signature heuristics."""
    content = await file.read()
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
def scan_text(req: TextScanRequest, db: Session = Depends(get_db)):
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
def scan_network(req: NetworkScanRequest, db: Session = Depends(get_db)):
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
def list_threat_events(limit: int = 50, db: Session = Depends(get_db)):
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
