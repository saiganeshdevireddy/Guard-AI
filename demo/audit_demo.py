"""Demonstrate Guard AI audit verification and tamper detection safely."""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.core.audit_chain import AuditChainService


PIPELINE_URL = "http://127.0.0.1:8000/api/pipeline/event"
EVENTS = [
    {"type": "link", "value": "https://example.com", "source": "audit-demo"},
    {"type": "link", "value": "https://a.b.example.com/verify", "source": "audit-demo"},
    {"type": "link", "value": "http://microsoft-verify-account.xyz", "source": "audit-demo"},
]


def post_event(payload: dict) -> dict:
    request = Request(
        PIPELINE_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def verify(database_url: str) -> dict:
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    session = sessionmaker(bind=engine)()
    try:
        return AuditChainService.verify_integrity(session)
    finally:
        session.close()
        engine.dispose()


def main() -> int:
    for payload, expected in zip(EVENTS, ("Safe", "Careful", "Danger")):
        try:
            response = post_event(payload)
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"Could not call Guard AI at {PIPELINE_URL}: {exc}", file=sys.stderr)
            return 1
        if response.get("verdict") != expected:
            print(f"Expected {expected}, got {response.get('verdict')!r}", file=sys.stderr)
            return 1
        print(f"Pipeline event: {expected}")

    url = make_url(settings.DATABASE_URL)
    if not url.drivername.startswith("sqlite") or not url.database:
        print("This demo requires the backend to use a SQLite database.", file=sys.stderr)
        return 1
    database_path = Path(url.database).resolve()
    if not database_path.is_file():
        print(f"Configured SQLite database not found: {database_path}", file=sys.stderr)
        return 1

    before = verify(settings.DATABASE_URL)
    if not before.get("valid"):
        print("The original audit chain is already invalid; refusing to continue.", file=sys.stderr)
        return 1
    print("CHAIN VALID")

    with tempfile.TemporaryDirectory(prefix="guard-ai-audit-demo-") as temporary_directory:
        copied_database = Path(temporary_directory) / "audit-copy.sqlite3"
        source_uri = f"file:{database_path.as_posix()}?mode=ro"
        with closing(sqlite3.connect(source_uri, uri=True)) as source:
            with closing(sqlite3.connect(copied_database)) as target:
                source.backup(target)

        copied_url = f"sqlite:///{copied_database.as_posix()}"
        # Tamper with one row only in the temporary copy.
        with closing(sqlite3.connect(copied_database)) as copy_db:
            row = copy_db.execute("SELECT id, event_type FROM audit_entries ORDER BY id DESC LIMIT 1").fetchone()
            if row is None:
                print("Copied database contains no audit entries.", file=sys.stderr)
                return 1
            broken_id, original_event_type = row
            copy_db.execute(
                "UPDATE audit_entries SET event_type = ? WHERE id = ?",
                (f"{original_event_type}_TAMPERED", broken_id),
            )
            copy_db.commit()

        after = verify(copied_url)
        if after.get("valid") or after.get("compromised_id") != broken_id:
            print(f"Expected tampering to be detected at entry {broken_id}; got {after}", file=sys.stderr)
            return 1
        print(f"TAMPER DETECTED - broken entry #{after['compromised_id']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
