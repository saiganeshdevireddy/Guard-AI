"""Shared, local-only inspection result normalization and private report storage."""
import hashlib
import json
import secrets
from datetime import datetime, timezone

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import InspectionReportRecord


class InspectionStorageError(RuntimeError):
    pass


def normalize_verdict(score: int, *, detected_malicious: bool = False) -> str:
    """Heuristics can find risk; absence of indicators is never proof of safety."""
    if detected_malicious or score >= 70:
        return "Malicious"
    if score > 0:
        return "Suspicious"
    return "Unknown"


def record_inspection(db: Session, *, owner_id: str, inspection_type: str,
                      content: bytes | None, score: int, findings: list[str],
                      limitations: list[str]) -> dict:
    digest = hashlib.sha256(content).hexdigest() if content is not None else None
    report = InspectionReportRecord(
        report_id=secrets.token_urlsafe(24), owner_id=owner_id,
        inspection_type=inspection_type, artifact_sha256=digest,
        verdict=normalize_verdict(score), score=max(0, min(100, int(score))),
        findings_json=json.dumps([str(x)[:500] for x in findings[:50]], ensure_ascii=False),
        limitations_json=json.dumps([str(x)[:500] for x in limitations[:20]], ensure_ascii=False),
        created_at=datetime.now(timezone.utc),
    )
    try:
        db.add(report)
        db.commit()
        db.refresh(report)
    except SQLAlchemyError:
        db.rollback()
        raise InspectionStorageError("Inspection report could not be persisted") from None
    return serialize_report(report)


def serialize_report(report: InspectionReportRecord) -> dict:
    return {
        "report_id": report.report_id,
        "type": report.inspection_type,
        "verdict": report.verdict,
        "score": report.score,
        "sha256": report.artifact_sha256,
        "findings": json.loads(report.findings_json or "[]"),
        "limitations": json.loads(report.limitations_json or "[]"),
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }
