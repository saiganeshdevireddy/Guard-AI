"""Worker protocol tests use generated test-only certificates; no real worker exists."""
import base64
import hashlib
import json
import secrets
import ssl
import tempfile
import threading
import asyncio
import jwt
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request as URLRequest, urlopen

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from app.database import (
    AuditEntry,
    BrowserSessionRecord,
    SessionLocal,
    WorkerAuthorizationTicketRecord,
    WorkerHealthRecord,
    WorkerIdentityRecord,
    WorkerSigningKeyState,
    get_db,
    init_db,
)
from app.main import app
from app.agents.controller import controller_ai
from app.security.auth import issue_access_token
from app.services.worker_communication import (
    DatabaseWorkerRegistry,
    WorkerCommunicationService,
    WorkerHealthEvidence,
    WorkerSecurityError,
    certificate_fingerprint,
)
from app.services.browser_session_manager import BrowserPrincipal, BrowserSessionPolicy, WorkerHealth
from app.core.audit_chain import AuditChainService

init_db()


@pytest.fixture(autouse=True)
def clear_dependency_overrides(monkeypatch):
    app.dependency_overrides.clear()
    monkeypatch.setattr(controller_ai.defence, "_browser_session_policy_enabled", True)
    db = SessionLocal()
    try:
        db.query(WorkerAuthorizationTicketRecord).delete()
        db.query(WorkerHealthRecord).delete()
        db.query(WorkerIdentityRecord).delete()
        db.query(WorkerSigningKeyState).delete()
        db.query(BrowserSessionRecord).filter(BrowserSessionRecord.worker_id.is_not(None)).delete()
        db.commit()
    finally:
        db.close()
    yield
    app.dependency_overrides.clear()


def _make_certificates(*, expired=False, revoked=False, expired_crl=False):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Guard AI Test Worker CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "worker-test-01")])
    not_before = now - timedelta(days=3) if expired else now - timedelta(minutes=1)
    not_after = now - timedelta(days=1) if expired else now + timedelta(days=2)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("worker-test-01")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH
        ]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    crl_builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(now - timedelta(minutes=1))
        .next_update(now - timedelta(minutes=1) if expired_crl else now + timedelta(days=7))
    )
    if revoked:
        revoked_certificate = (
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.serial_number)
            .revocation_date(now - timedelta(minutes=1))
            .build()
        )
        crl_builder = crl_builder.add_revoked_certificate(revoked_certificate)
    crl = crl_builder.sign(ca_key, hashes.SHA256())
    pem = lambda cert: cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return ca, leaf, leaf_key, pem(ca), pem(leaf), crl_pem


def _service(ca_pem, crl_pem, *, secret="test-only-worker-ticket-signing-key-32-bytes", key_id="v1", previous=None, clock=None):
    return WorkerCommunicationService(
        ca_pem=ca_pem, crl_pem=crl_pem, ticket_secret=secret, ticket_key_id=key_id,
        previous_ticket_keys=previous or {}, clock=clock,
    )


def _register(service, leaf_pem, worker_id="worker-test-01"):
    db = SessionLocal()
    try:
        return service.register_worker(
            db, worker_id=worker_id, certificate_pem=leaf_pem,
            intermediate_pems=[], actor="pytest-admin",
        )
    finally:
        db.close()


def _register_with_healthy_evidence(service, leaf_pem, leaf_key, worker_id="worker-test-01"):
    worker = _register(service, leaf_pem, worker_id)
    db = SessionLocal()
    try:
        service.accept_health_evidence(
            db, peer_worker=worker, evidence=_health_evidence(leaf_key, worker_id=worker_id)
        )
    finally:
        db.close()
    return worker


def _seed_session(worker_id, owner="pytest-admin", state="AUTHORIZED"):
    session_id = secrets.token_urlsafe(24)
    db = SessionLocal()
    try:
        db.add(BrowserSessionRecord(
            session_id=session_id,
            owner_id=owner,
            idempotency_key_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
            state=state,
            worker_id=worker_id,
            policy_version="browser-session-policy-v1",
            authorized_at=datetime.now(timezone.utc),
        ))
        db.commit()
    finally:
        db.close()
    return session_id


def _health_evidence(cert_key, *, worker_id="worker-test-01", status="HEALTHY", observed=None, sequence=1):
    observed = observed or datetime.now(timezone.utc)
    nonce = secrets.token_urlsafe(24)
    evidence = WorkerHealthEvidence(worker_id, status, observed, sequence, nonce, "placeholder")
    signature = cert_key.sign(evidence.signed_bytes(), asymmetric_padding.PKCS1v15(), hashes.SHA256())
    return WorkerHealthEvidence(
        worker_id, status, observed, sequence, nonce,
        base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    )


class _TLSASGIBridge(BaseHTTPRequestHandler):
    """Test-only TLS server bridge that passes the real SSL peer cert as ASGI TLS evidence."""
    server_version = "GuardAITestTLS/1"

    def log_message(self, _format, *_args):
        return  # Never log ticket request/response data in this test bridge.

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        peer_cert = self.connection.getpeercert(binary_form=True)
        headers = [(key.lower().encode("latin1"), value.encode("latin1")) for key, value in self.headers.items()]
        sent = []
        received = False

        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        from urllib.parse import urlsplit
        target = urlsplit(self.path)
        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "method": "POST", "scheme": "https",
            "path": target.path, "raw_path": target.path.encode(), "query_string": target.query.encode(),
            "headers": headers, "client": self.client_address, "server": self.server.server_address,
            "extensions": {"tls": {"client_cert": peer_cert}},
        }
        asyncio.run(self.server.asgi_app(scope, receive, send))
        start = next(message for message in sent if message["type"] == "http.response.start")
        response_body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
        self.send_response(start["status"])
        for name, value in start.get("headers", []):
            self.send_header(name.decode("latin1"), value.decode("latin1"))
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)


class _LocalMTLSServer:
    def __init__(self, ca_pem, cert_pem, private_key):
        self.temp = tempfile.TemporaryDirectory(prefix="guard-ai-mtls-test-")
        root = Path(self.temp.name)
        self.ca_path = root / "ca.pem"
        self.cert_path = root / "worker.pem"
        self.key_path = root / "worker-key.pem"
        self.ca_path.write_text(ca_pem, encoding="ascii")
        self.cert_path.write_text(cert_pem, encoding="ascii")
        self.key_path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(self.cert_path), str(self.key_path))
        tls.verify_mode = ssl.CERT_REQUIRED
        tls.load_verify_locations(cafile=str(self.ca_path))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _TLSASGIBridge)
        self.server.asgi_app = app
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"https://127.0.0.1:{self.server.server_address[1]}"
        self.client_context = ssl.create_default_context(cafile=str(self.ca_path))
        self.client_context.check_hostname = False
        self.client_context.load_cert_chain(str(self.cert_path), str(self.key_path))

    def post(self, path, body, headers=None, context=None):
        request = URLRequest(
            self.url + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", **(headers or {})},
            method="POST",
        )
        try:
            with urlopen(request, context=context or self.client_context, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()


def test_admin_registration_requires_trusted_ca_and_records_audit(test_auth_users):
    ca, leaf, _, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    record = _register(service, leaf_pem)
    assert record.status == "ACTIVE"
    assert record.certificate_fingerprint == certificate_fingerprint(leaf)
    db = SessionLocal()
    try:
        event = db.query(AuditEntry).filter_by(event_type="WORKER_IDENTITY_REGISTERED").one()
        assert event.actor == "pytest-admin"
    finally:
        db.close()


def test_registration_rejects_untrusted_or_expired_certificate():
    _, _, _, _, leaf_pem, _ = _make_certificates()
    other_ca, _, _, other_ca_pem, _, other_crl_pem = _make_certificates()
    service = _service(other_ca_pem, other_crl_pem)
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError):
            service.register_worker(db, worker_id="bad-worker", certificate_pem=leaf_pem,
                                   intermediate_pems=[], actor="pytest-admin")
    finally:
        db.close()


def test_ca_revoked_certificate_and_missing_crl_fail_closed():
    _, _, _, ca_pem, revoked_leaf, revoked_crl = _make_certificates(revoked=True)
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError, match="revoked"):
            _service(ca_pem, revoked_crl).register_worker(
                db, worker_id="ca-revoked-worker", certificate_pem=revoked_leaf,
                intermediate_pems=[], actor="pytest-admin",
            )
        _, _, _, trusted_ca, trusted_leaf, _ = _make_certificates()
        with pytest.raises(WorkerSecurityError, match="revocation list"):
            _service(trusted_ca, "").register_worker(
                db, worker_id="crl-missing-worker", certificate_pem=trusted_leaf,
                intermediate_pems=[], actor="pytest-admin",
            )
    finally:
        db.close()


def test_expired_or_malformed_crl_fails_closed():
    _, _, _, ca_pem, leaf_pem, expired_crl = _make_certificates(expired_crl=True)
    _, _, _, current_ca, _, _ = _make_certificates()
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError):
            _service(ca_pem, expired_crl).register_worker(
                db, worker_id="expired-crl-worker", certificate_pem=leaf_pem,
                intermediate_pems=[], actor="pytest-admin",
            )
        with pytest.raises(WorkerSecurityError):
            _service(current_ca, "not-a-crl").register_worker(
                db, worker_id="malformed-crl-worker", certificate_pem=leaf_pem,
                intermediate_pems=[], actor="pytest-admin",
            )
    finally:
        db.close()

    _, _, _, ca_pem, expired_leaf_pem, crl_pem = _make_certificates(expired=True)
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError):
            _service(ca_pem, crl_pem).register_worker(db, worker_id="expired-worker",
                                             certificate_pem=expired_leaf_pem,
                                             intermediate_pems=[], actor="pytest-admin")
    finally:
        db.close()


def test_duplicate_and_revoked_worker_identity_remain_rejected():
    _, leaf, _, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register(service, leaf_pem)
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError):
            service.register_worker(db, worker_id="worker-test-01", certificate_pem=leaf_pem,
                                   intermediate_pems=[], actor="pytest-admin")
        assert service.revoke_worker(db, worker_id="worker-test-01", actor="pytest-admin") is True
        with pytest.raises(WorkerSecurityError):
            service.authenticate_peer_certificate(db, leaf.public_bytes(serialization.Encoding.DER))
        assert service.revoke_worker(db, worker_id="worker-test-01", actor="pytest-admin") is False
        assert db.query(AuditEntry).filter_by(event_type="WORKER_IDENTITY_REVOKED").count() == 1
    finally:
        db.close()


def test_worker_certificate_renewal_revokes_old_fingerprint_and_audits():
    _, old_leaf, _, old_ca, old_cert, old_crl = _make_certificates()
    _, new_leaf, _, new_ca, new_cert, new_crl = _make_certificates()
    service = _service(old_ca + new_ca, old_crl + new_crl)
    _register(service, old_cert)
    db = SessionLocal()
    try:
        renewed = service.renew_worker_certificate(
            db, worker_id="worker-test-01", certificate_pem=new_cert,
            intermediate_pems=[], actor="pytest-admin",
        )
        assert renewed.certificate_fingerprint == certificate_fingerprint(new_leaf)
        with pytest.raises(WorkerSecurityError):
            service.authenticate_peer_certificate(db, old_leaf.public_bytes(serialization.Encoding.DER))
        assert service.authenticate_peer_certificate(
            db, new_leaf.public_bytes(serialization.Encoding.DER)
        ).worker_id == "worker-test-01"
        event = db.query(AuditEntry).filter_by(event_type="WORKER_CERTIFICATE_RENEWED").one()
        assert event.actor == "pytest-admin"
    finally:
        db.close()


def test_registration_audit_failure_rolls_back_identity(monkeypatch):
    _, _, _, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    monkeypatch.setattr(
        AuditChainService,
        "record_event",
        classmethod(lambda cls, db, **kwargs: (_ for _ in ()).throw(RuntimeError("audit unavailable"))),
    )
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError):
            service.register_worker(
                db, worker_id="rollback-worker", certificate_pem=leaf_pem,
                intermediate_pems=[], actor="pytest-admin",
            )
    finally:
        db.close()
    db = SessionLocal()
    try:
        assert db.query(WorkerIdentityRecord).filter_by(worker_id="rollback-worker").one_or_none() is None
    finally:
        db.close()


def test_peer_certificate_must_be_registered_and_valid():
    ca, leaf, _, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError):
            service.authenticate_peer_certificate(db, leaf.public_bytes(serialization.Encoding.DER))
        _register(service, leaf_pem)
        peer = service.authenticate_peer_certificate(db, leaf.public_bytes(serialization.Encoding.DER))
        assert peer.worker_id == "worker-test-01"
    finally:
        db.close()


def test_session_ticket_is_bound_expires_and_can_only_be_redeemed_once():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")
    db = SessionLocal()
    try:
        ticket_id, ticket, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="delivery-request-session-01",
        )
        accepted = service.redeem_session_ticket(
            db, token=ticket, peer_worker_id="worker-test-01", expected_session_id=session_id
        )
        assert accepted == {"session_id": session_id, "worker_id": "worker-test-01", "subject_id": "pytest-admin"}
        with pytest.raises(WorkerSecurityError):
            service.redeem_session_ticket(
                db, token=ticket, peer_worker_id="worker-test-01", expected_session_id=session_id
            )
        assert db.query(WorkerAuthorizationTicketRecord).filter_by(ticket_id=ticket_id).one().redeemed_at
    finally:
        db.close()


def test_ticket_delivery_retry_returns_same_token_and_does_not_mint_duplicates():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")
    db = SessionLocal()
    try:
        first = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="stable-delivery-request-001",
        )
        retry = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="stable-delivery-request-001",
        )
        assert first == retry
        assert db.query(WorkerAuthorizationTicketRecord).filter_by(
            worker_id="worker-test-01"
        ).count() == 1
        with pytest.raises(WorkerSecurityError):
            service.issue_session_ticket(
                db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
                delivery_id="different-delivery-request-02",
            )
        service.redeem_session_ticket(
            db, token=first[1], peer_worker_id="worker-test-01", expected_session_id=session_id
        )
        with pytest.raises(WorkerSecurityError):
            service.issue_session_ticket(
                db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
                delivery_id="stable-delivery-request-001",
            )
    finally:
        db.close()


def test_ticket_signing_key_rotation_accepts_configured_previous_key_and_audits_ids():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    old_key = "old-worker-ticket-signing-secret-0001"
    new_key = "new-worker-ticket-signing-secret-0002"
    old_service = _service(ca_pem, crl_pem, secret=old_key, key_id="key-2026-01")
    _register_with_healthy_evidence(old_service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")
    db = SessionLocal()
    try:
        _, ticket, _ = old_service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="rotation-delivery-request-01",
        )
        new_service = _service(
            ca_pem, crl_pem, secret=new_key, key_id="key-2026-02",
            previous={"key-2026-01": old_key},
        )
        assert new_service.redeem_session_ticket(
            db, token=ticket, peer_worker_id="worker-test-01", expected_session_id=session_id
        )["session_id"] == session_id
        assert new_service.record_key_configuration(db, actor="pytest-admin") is True
        assert new_service.record_key_configuration(db, actor="pytest-admin") is False
        rotated = _service(ca_pem, crl_pem, secret="third-worker-ticket-signing-secret-0003", key_id="key-2026-03")
        assert rotated.record_key_configuration(db, actor="pytest-admin") is True
        assert db.query(AuditEntry).filter_by(event_type="WORKER_TICKET_SIGNING_KEY_ROTATED").count() == 1
        assert db.query(WorkerSigningKeyState).filter_by(id=1).one().active_key_id == "key-2026-03"
    finally:
        db.close()


def test_ticket_with_unknown_key_id_is_rejected_even_when_signed_by_known_key():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    secret = "known-worker-ticket-signing-secret-0001"
    service = _service(ca_pem, crl_pem, secret=secret, key_id="known-v1")
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")
    db = SessionLocal()
    try:
        _, token, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="unknown-kid-delivery-0001",
        )
        claims = jwt.decode(token, options={"verify_signature": False})
        unknown_kid = jwt.encode(claims, secret, algorithm="HS256", headers={"kid": "unknown-v2"})
        with pytest.raises(WorkerSecurityError):
            service.redeem_session_ticket(
                db, token=unknown_kid, peer_worker_id="worker-test-01", expected_session_id=session_id
            )
        row = db.query(WorkerAuthorizationTicketRecord).filter_by(session_id=session_id).one()
        assert row.redeemed_at is None
    finally:
        db.close()


@pytest.mark.parametrize("mismatch", ["session", "worker"])
def test_ticket_identity_mismatch_is_rejected(mismatch):
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")
    db = SessionLocal()
    try:
        _, ticket, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id=f"delivery-request-{mismatch}-01",
        )
        with pytest.raises(WorkerSecurityError):
            service.redeem_session_ticket(
                db,
                token=ticket,
                peer_worker_id="other-worker" if mismatch == "worker" else "worker-test-01",
                expected_session_id="other-session" if mismatch == "session" else session_id,
            )
    finally:
        db.close()


def test_ticket_redeem_rechecks_persisted_session_authorization():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")
    db = SessionLocal()
    try:
        _, ticket, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="session-state-delivery-0001",
        )
        session = db.query(BrowserSessionRecord).filter_by(session_id=session_id).one()
        session.state = "DENIED"
        db.commit()
        with pytest.raises(WorkerSecurityError):
            service.redeem_session_ticket(
                db, token=ticket, peer_worker_id="worker-test-01", expected_session_id=session_id
            )
    finally:
        db.close()


def test_worker_becoming_unhealthy_after_session_authorization_cannot_redeem_ticket():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    issue_session = _seed_session(worker.worker_id)
    redeem_session = _seed_session(worker.worker_id)
    db = SessionLocal()
    try:
        _, ticket, _ = service.issue_session_ticket(
            db, session_id=redeem_session, subject_id="pytest-admin", worker_id=worker.worker_id,
            delivery_id="unhealthy-after-auth-ticket-01",
        )
        service.accept_health_evidence(
            db, peer_worker=worker,
            evidence=_health_evidence(leaf_key, status="UNHEALTHY", sequence=2),
        )
        with pytest.raises(WorkerSecurityError, match="health"):
            service.issue_session_ticket(
                db, session_id=issue_session, subject_id="pytest-admin", worker_id=worker.worker_id,
                delivery_id="unhealthy-before-issue-ticket-01",
            )
        with pytest.raises(WorkerSecurityError, match="health"):
            service.redeem_session_ticket(
                db, token=ticket, peer_worker_id=worker.worker_id, expected_session_id=redeem_session
            )
        record = db.query(WorkerAuthorizationTicketRecord).filter_by(session_id=redeem_session).one()
        assert record.redeemed_at is None
    finally:
        db.close()


def test_missing_or_invalid_persisted_health_denies_ticket_authorization():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register(service, leaf_pem)
    session_id = _seed_session(worker.worker_id)
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError, match="health"):
            service.issue_session_ticket(
                db, session_id=session_id, subject_id="pytest-admin", worker_id=worker.worker_id,
                delivery_id="missing-health-ticket-000001",
            )
        service.accept_health_evidence(
            db, peer_worker=worker, evidence=_health_evidence(leaf_key, sequence=1)
        )
        row = db.query(WorkerHealthRecord).filter_by(worker_id=worker.worker_id).one()
        row.signature_b64url = base64.urlsafe_b64encode(b"bad-signature" * 8).decode("ascii").rstrip("=")
        db.commit()
        with pytest.raises(WorkerSecurityError, match="health"):
            service.issue_session_ticket(
                db, session_id=session_id, subject_id="pytest-admin", worker_id=worker.worker_id,
                delivery_id="invalid-health-ticket-00001",
            )
        service.accept_health_evidence(
            db, peer_worker=worker, evidence=_health_evidence(leaf_key, sequence=2)
        )
        _, ticket, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id=worker.worker_id,
            delivery_id="invalid-health-redeem-0001",
        )
        row = db.query(WorkerHealthRecord).filter_by(worker_id=worker.worker_id).one()
        row.signature_b64url = base64.urlsafe_b64encode(b"bad-signature" * 8).decode("ascii").rstrip("=")
        db.commit()
        with pytest.raises(WorkerSecurityError, match="health"):
            service.redeem_session_ticket(
                db, token=ticket, peer_worker_id=worker.worker_id, expected_session_id=session_id
            )
    finally:
        db.close()


def test_stale_worker_health_denies_ticket_issuance_and_redemption():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    issue_session = _seed_session(worker.worker_id)
    redeem_session = _seed_session(worker.worker_id)
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        service.clock = lambda: now + timedelta(seconds=31)
        with pytest.raises(WorkerSecurityError, match="health"):
            service.issue_session_ticket(
                db, session_id=issue_session, subject_id="pytest-admin", worker_id=worker.worker_id,
                delivery_id="stale-before-issue-ticket-01",
            )
        service.clock = lambda: now
        _, ticket, _ = service.issue_session_ticket(
            db, session_id=redeem_session, subject_id="pytest-admin", worker_id=worker.worker_id,
            delivery_id="stale-before-redeem-ticket-01",
        )
        service.clock = lambda: now + timedelta(seconds=31)
        with pytest.raises(WorkerSecurityError, match="health"):
            service.redeem_session_ticket(
                db, token=ticket, peer_worker_id=worker.worker_id, expected_session_id=redeem_session
            )
    finally:
        db.close()


def test_defence_policy_is_rechecked_for_ticket_issue_and_redemption(monkeypatch):
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    issue_session = _seed_session(worker.worker_id)
    redeem_session = _seed_session(worker.worker_id)
    db = SessionLocal()
    try:
        monkeypatch.setattr(controller_ai.defence, "_browser_session_policy_enabled", False)
        with pytest.raises(WorkerSecurityError, match="Defence"):
            service.issue_session_ticket(
                db, session_id=issue_session, subject_id="pytest-admin", worker_id=worker.worker_id,
                delivery_id="defence-disabled-issue-ticket-01",
            )
        monkeypatch.setattr(controller_ai.defence, "_browser_session_policy_enabled", True)
        _, ticket, _ = service.issue_session_ticket(
            db, session_id=redeem_session, subject_id="pytest-admin", worker_id=worker.worker_id,
            delivery_id="defence-disabled-redeem-ticket-01",
        )
        monkeypatch.setattr(controller_ai.defence, "_browser_session_policy_enabled", False)
        with pytest.raises(WorkerSecurityError, match="Defence"):
            service.redeem_session_ticket(
                db, token=ticket, peer_worker_id=worker.worker_id, expected_session_id=redeem_session
            )
        row = db.query(WorkerAuthorizationTicketRecord).filter_by(session_id=redeem_session).one()
        assert row.redeemed_at is None
    finally:
        db.close()


def test_worker_revoked_between_ticket_issue_and_redemption_is_denied():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session(worker.worker_id)
    db = SessionLocal()
    try:
        _, ticket, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id=worker.worker_id,
            delivery_id="revoked-after-issue-ticket-01",
        )
        service.revoke_worker(db, worker_id=worker.worker_id, actor="pytest-admin")
        with pytest.raises(WorkerSecurityError):
            service.redeem_session_ticket(
                db, token=ticket, peer_worker_id=worker.worker_id, expected_session_id=session_id
            )
    finally:
        db.close()


def test_database_failure_during_ticket_reauthorization_fails_closed():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session(worker.worker_id)

    class FailingHealthQuerySession(Session):
        def query(self, *entities, **kwargs):
            if entities and entities[0] is WorkerHealthRecord:
                raise SQLAlchemyError("simulated health database outage")
            return super().query(*entities, **kwargs)

    db = FailingHealthQuerySession(bind=SessionLocal.kw["bind"], autocommit=False, autoflush=False)
    try:
        with pytest.raises(WorkerSecurityError, match="authorization storage"):
            service.issue_session_ticket(
                db, session_id=session_id, subject_id="pytest-admin", worker_id=worker.worker_id,
                delivery_id="health-db-failure-ticket-01",
            )
    finally:
        db.rollback()
        db.close()


def test_concurrent_ticket_redemption_succeeds_exactly_once():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session(worker.worker_id)
    db = SessionLocal()
    try:
        _, ticket, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id=worker.worker_id,
            delivery_id="concurrent-redeem-ticket-01",
        )
    finally:
        db.close()

    barrier = threading.Barrier(2)

    def redeem_once(_):
        session = SessionLocal()
        try:
            barrier.wait(timeout=3)
            service.redeem_session_ticket(
                session, token=ticket, peer_worker_id=worker.worker_id, expected_session_id=session_id
            )
            return True
        except WorkerSecurityError:
            return False
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(redeem_once, range(2)))
    assert results.count(True) == 1
    assert results.count(False) == 1


def test_ticket_write_failure_rolls_back(test_auth_users):
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")

    class FailingCommitSession(Session):
        def commit(self):
            self.flush()
            raise SQLAlchemyError("simulated ticket commit failure")

    failing_db = FailingCommitSession(bind=SessionLocal.kw["bind"], autocommit=False, autoflush=False)
    try:
        with pytest.raises(WorkerSecurityError):
            service.issue_session_ticket(
                failing_db, session_id=session_id, subject_id="pytest-admin",
                worker_id="worker-test-01", delivery_id="ticket-write-failure-0001",
            )
    finally:
        failing_db.rollback()
        failing_db.close()
    db = SessionLocal()
    try:
        assert db.query(WorkerAuthorizationTicketRecord).filter_by(session_id=session_id).one_or_none() is None
    finally:
        db.close()


def test_ticket_issue_and_redemption_are_audited_without_recording_bearer_token():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")
    db = SessionLocal()
    try:
        ticket_id, token, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="audit-ticket-delivery-0001",
        )
        service.redeem_session_ticket(
            db, token=token, peer_worker_id="worker-test-01", expected_session_id=session_id
        )
        event_types = {event.event_type for event in db.query(AuditEntry).filter(
            AuditEntry.event_type.in_([
                "WORKER_AUTHORIZATION_TICKET_ISSUED",
                "WORKER_AUTHORIZATION_TICKET_REDEEMED",
            ])
        )}
        assert event_types == {
            "WORKER_AUTHORIZATION_TICKET_ISSUED", "WORKER_AUTHORIZATION_TICKET_REDEEMED"
        }
        assert db.query(WorkerAuthorizationTicketRecord).filter_by(ticket_id=ticket_id).one()
        assert token not in repr(db.query(AuditEntry).all())
    finally:
        db.close()


def test_ticket_issue_audit_failure_does_not_return_or_persist_ticket(monkeypatch):
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")

    def fail_audit(*_args, **_kwargs):
        raise SQLAlchemyError("simulated audit outage")

    monkeypatch.setattr(AuditChainService, "record_event", fail_audit)
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError, match="audit is unavailable"):
            service.issue_session_ticket(
                db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
                delivery_id="audit-failure-delivery-0001",
            )
        db.rollback()
        assert db.query(WorkerAuthorizationTicketRecord).filter_by(session_id=session_id).count() == 0
    finally:
        db.close()


def test_invalid_health_evidence_is_audited_without_signature_or_payload():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register(service, leaf_pem)
    invalid = _health_evidence(leaf_key)
    invalid = WorkerHealthEvidence(
        invalid.worker_id, invalid.status, invalid.observed_at, invalid.sequence, invalid.nonce,
        base64.urlsafe_b64encode(b"invalid-signature-material" * 3).decode("ascii").rstrip("="),
    )
    db = SessionLocal()
    try:
        with pytest.raises(WorkerSecurityError):
            service.accept_health_evidence(db, peer_worker=worker, evidence=invalid)
        event = db.query(AuditEntry).filter_by(event_type="WORKER_HEALTH_EVIDENCE_REJECTED").one()
        assert event.actor == "worker:worker-test-01"
        assert invalid.signature_b64url not in repr(event)
    finally:
        db.close()


@pytest.mark.parametrize("secret,key_id,previous", [
    ("short", "v1", {}),
    ("valid-worker-ticket-secret-material-01", 42, {}),
    ("valid-worker-ticket-secret-material-01", "v1", {"bad key": "x" * 32}),
])
def test_malformed_ticket_key_configuration_fails_closed(secret, key_id, previous):
    service = WorkerCommunicationService(
        ca_pem="", crl_pem="", ticket_secret=secret, ticket_key_id=key_id,
        previous_ticket_keys=previous,
    )
    assert service.ticket_configuration_valid is False


def test_expired_ticket_and_revoked_ticket_fail_closed():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    _register_with_healthy_evidence(service, leaf_pem, leaf_key)
    session_id = _seed_session("worker-test-01")
    expired_session_id = _seed_session("worker-test-01")
    now = datetime.now(timezone.utc)
    service.clock = lambda: now
    db = SessionLocal()
    try:
        ticket_id, ticket, _ = service.issue_session_ticket(
            db, session_id=session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="delivery-expiry-request-01",
            ttl=timedelta(seconds=10),
        )
        assert service.revoke_ticket(db, ticket_id=ticket_id, actor="pytest-admin")
        with pytest.raises(WorkerSecurityError):
            service.redeem_session_ticket(
                db, token=ticket, peer_worker_id="worker-test-01", expected_session_id=session_id
            )
    finally:
        db.close()

    later = now + timedelta(seconds=15)
    expired_service = _service(ca_pem, crl_pem, clock=lambda: later)
    db = SessionLocal()
    try:
        # Token expiry is cryptographically checked before database redemption.
        _, expired_ticket, _ = service.issue_session_ticket(
            db, session_id=expired_session_id, subject_id="pytest-admin", worker_id="worker-test-01",
            delivery_id="delivery-expiry-request-02",
            ttl=timedelta(seconds=10),
        )
        with pytest.raises(WorkerSecurityError):
            expired_service.redeem_session_ticket(
                db, token=expired_ticket, peer_worker_id="worker-test-01", expected_session_id=expired_session_id
            )
    finally:
        db.close()


def test_health_signature_freshness_sequence_and_identity_are_enforced():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register(service, leaf_pem)
    db = SessionLocal()
    try:
        evidence = _health_evidence(leaf_key)
        health = service.accept_health_evidence(db, peer_worker=worker, evidence=evidence)
        assert health.status == "HEALTHY"
        assert service.current_health(db, worker_id=worker.worker_id) == "HEALTHY"
        with pytest.raises(WorkerSecurityError):
            service.accept_health_evidence(db, peer_worker=worker, evidence=evidence)
        with pytest.raises(WorkerSecurityError):
            service.accept_health_evidence(
                db, peer_worker=worker,
                evidence=_health_evidence(leaf_key, sequence=2, observed=datetime.now(timezone.utc)-timedelta(minutes=2)),
            )
        with pytest.raises(WorkerSecurityError):
            service.accept_health_evidence(
                db, peer_worker=worker, evidence=_health_evidence(leaf_key, worker_id="other-worker", sequence=3)
            )
        bad = _health_evidence(leaf_key, sequence=4)
        forged = WorkerHealthEvidence(
            bad.worker_id, bad.status, bad.observed_at, bad.sequence, bad.nonce,
            base64.urlsafe_b64encode(b"invalid signature" * 4).decode().rstrip("="),
        )
        with pytest.raises(WorkerSecurityError):
            service.accept_health_evidence(db, peer_worker=worker, evidence=forged)
    finally:
        db.close()


def test_lifecycle_policy_independently_consumes_verified_database_health(monkeypatch):
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register(service, leaf_pem)
    session_id = _seed_session(worker.worker_id)
    from app.agents.controller import controller_ai
    monkeypatch.setattr(controller_ai.defence, "_browser_session_policy_enabled", True)
    principal = BrowserPrincipal("pytest-admin", frozenset({"sandbox:write"}))
    policy = BrowserSessionPolicy(health_max_age=timedelta(seconds=30))
    db = SessionLocal()
    try:
        registry = DatabaseWorkerRegistry(db, service)
        assert registry.get_available_worker_id() is None  # Enrollment alone is not health.
        service.accept_health_evidence(
            db, peer_worker=worker, evidence=_health_evidence(leaf_key, sequence=1)
        )
        available_id = registry.get_available_worker_id()
        assert available_id == worker.worker_id
        allowed = policy.evaluate_launch(
            principal=principal, owner_id=principal.subject,
            explicit_user_authorization=True, defence_policy_enabled=True,
            worker_id=available_id, worker_registry=registry,
        )
        assert allowed.allowed is True
        registration = registry.get_registration(worker.worker_id)
        assert controller_ai.defence.authorizes_browser_worker(
            registration, now=datetime.now(timezone.utc), max_age=timedelta(seconds=30)
        ) is True

        service.accept_health_evidence(
            db, peer_worker=worker,
            evidence=_health_evidence(leaf_key, status="UNHEALTHY", sequence=2),
        )
        denied = policy.evaluate_launch(
            principal=principal, owner_id=principal.subject,
            explicit_user_authorization=True, defence_policy_enabled=True,
            worker_id=worker.worker_id, worker_registry=registry,
        )
        assert denied.allowed is False
        assert controller_ai.defence.authorizes_browser_worker(
            registry.get_registration(worker.worker_id),
            now=datetime.now(timezone.utc), max_age=timedelta(seconds=30),
        ) is False
        assert session_id  # Session creation remains metadata-only; policy doesn't provision it.
    finally:
        db.close()


def test_health_registry_reverifies_persisted_signature_instead_of_trusting_row():
    _, _, leaf_key, ca_pem, leaf_pem, crl_pem = _make_certificates()
    service = _service(ca_pem, crl_pem)
    worker = _register(service, leaf_pem)
    db = SessionLocal()
    try:
        service.accept_health_evidence(
            db, peer_worker=worker, evidence=_health_evidence(leaf_key, sequence=1)
        )
        row = db.query(WorkerHealthRecord).filter_by(worker_id=worker.worker_id).one()
        row.evidence_payload = row.evidence_payload.replace('"HEALTHY"', '"UNHEALTHY"')
        db.commit()
        registration = DatabaseWorkerRegistry(db, service).get_registration(worker.worker_id)
        assert registration.health is WorkerHealth.UNKNOWN
        assert registration.evidence_verified is False
    finally:
        db.close()


def test_stale_disconnected_and_revoked_worker_health_is_unknown():
    _, leaf, _, ca_pem, leaf_pem, crl_pem = _make_certificates()
    old = datetime.now(timezone.utc) - timedelta(minutes=2)
    service = _service(ca_pem, crl_pem, clock=lambda: datetime.now(timezone.utc))
    worker = _register(service, leaf_pem)
    db = SessionLocal()
    try:
        db.add(WorkerHealthRecord(
            worker_id=worker.worker_id, status="HEALTHY", observed_at=old.replace(tzinfo=None),
            sequence=1, evidence_hash="a" * 64,
        ))
        db.commit()
        assert service.current_health(db, worker_id=worker.worker_id) == "UNKNOWN"
        service.revoke_worker(db, worker_id=worker.worker_id, actor="pytest-admin")
        assert service.current_health(db, worker_id=worker.worker_id) == "UNKNOWN"
    finally:
        db.close()


def test_worker_admin_api_requires_auth_and_unconfigured_trust_fails_closed(test_auth_users, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "WORKER_CA_CERT_PEM", "")
    unauthenticated = TestClient(app).post(
        "/api/v1/workers/worker-test/register",
        json={"certificate_pem": "not a certificate", "intermediate_pems": []},
    )
    assert unauthenticated.status_code == 401
    token = issue_access_token(test_auth_users["admin_username"])
    response = TestClient(app, headers={"Authorization": f"Bearer {token}"}).post(
        "/api/v1/workers/worker-test/register",
        json={"certificate_pem": "-----BEGIN CERTIFICATE-----" + "A" * 64 + "-----END CERTIFICATE-----"},
    )
    assert response.status_code == 503

    analyst_token = issue_access_token(test_auth_users["analyst_username"])
    unauthorized = TestClient(app, headers={"Authorization": f"Bearer {analyst_token}"}).put(
        "/api/v1/workers/worker-test/certificate",
        json={"certificate_pem": "-----BEGIN CERTIFICATE-----" + "A" * 64 + "-----END CERTIFICATE-----"},
    )
    assert unauthorized.status_code == 403


def test_worker_tls_routes_reject_missing_certificate_and_ignore_spoofable_headers(test_auth_users):
    response = TestClient(app).post(
        "/api/v1/internal/workers/worker-test-01/sessions/abcdefghijklmnopqrstuvwxyz/redeem",
        headers={"X-Client-Cert": "spoofed"},
        json={"ticket": "a" * 64},
    )
    assert response.status_code == 401

    ticket_response = TestClient(app).post(
        "/api/v1/internal/workers/worker-test-01/sessions/abcdefghijklmnopqrstuvwxyz/ticket",
        headers={"X-Client-Cert": "spoofed", "Delivery-Id": "delivery-request-test-0001"},
        json={"session_id": "abcdefghijklmnopqrstuvwxyz"},
    )
    assert ticket_response.status_code == 401


def test_real_local_tls_handshake_validates_worker_health_and_rejects_missing_or_untrusted_cert(monkeypatch):
    from app.config import settings

    _, _, worker_key, ca_pem, worker_cert_pem, crl_pem = _make_certificates()
    monkeypatch.setattr(settings, "WORKER_CA_CERT_PEM", ca_pem)
    monkeypatch.setattr(settings, "WORKER_CRL_PEM", crl_pem)
    monkeypatch.setattr(settings, "WORKER_TICKET_SIGNING_KEY", "integration-test-worker-ticket-secret-0001")
    monkeypatch.setattr(settings, "WORKER_TICKET_SIGNING_KEY_ID", "integration-v1")
    monkeypatch.setattr(settings, "WORKER_TICKET_VERIFY_KEYS_JSON", "{}")
    _register(WorkerCommunicationService(), worker_cert_pem)
    server = _LocalMTLSServer(ca_pem, worker_cert_pem, worker_key)
    try:
        evidence = _health_evidence(worker_key)
        status_code, body = server.post("/api/v1/internal/workers/health", {
            "worker_id": evidence.worker_id,
            "status": evidence.status,
            "observed_at": evidence.observed_at.isoformat(),
            "sequence": evidence.sequence,
            "nonce": evidence.nonce,
            "signature_b64url": evidence.signature_b64url,
        })
        assert status_code == 200
        assert body["status"] == "HEALTHY"

        no_cert = ssl.create_default_context(cafile=str(server.ca_path))
        no_cert.check_hostname = False
        with pytest.raises((URLError, ssl.SSLError, OSError)):
            server.post("/api/v1/internal/workers/health", {}, context=no_cert)

        _, _, other_private, other_ca_pem, other_cert_pem, _ = _make_certificates()
        other_root = Path(server.temp.name) / "other-ca.pem"
        other_cert = Path(server.temp.name) / "other-worker.pem"
        other_key = Path(server.temp.name) / "other-worker-key.pem"
        other_root.write_text(other_ca_pem, encoding="ascii")
        other_cert.write_text(other_cert_pem, encoding="ascii")
        other_key.write_bytes(other_private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))
        untrusted_context = ssl.create_default_context(cafile=str(server.ca_path))
        untrusted_context.check_hostname = False
        untrusted_context.load_cert_chain(str(other_cert), str(other_key))
        with pytest.raises((URLError, ssl.SSLError, OSError)):
            server.post("/api/v1/internal/workers/health", {}, context=untrusted_context)
    finally:
        server.close()


def test_mtls_ticket_delivery_is_retry_safe_and_replay_rejected(monkeypatch):
    from app.config import settings

    _, _, worker_key, ca_pem, worker_cert_pem, crl_pem = _make_certificates()
    monkeypatch.setattr(settings, "WORKER_CA_CERT_PEM", ca_pem)
    monkeypatch.setattr(settings, "WORKER_CRL_PEM", crl_pem)
    monkeypatch.setattr(settings, "WORKER_TICKET_SIGNING_KEY", "integration-ticket-secret-material-0001")
    monkeypatch.setattr(settings, "WORKER_TICKET_SIGNING_KEY_ID", "integration-v1")
    monkeypatch.setattr(settings, "WORKER_TICKET_VERIFY_KEYS_JSON", "{}")
    _register(WorkerCommunicationService(), worker_cert_pem)
    session_id = _seed_session("worker-test-01")
    server = _LocalMTLSServer(ca_pem, worker_cert_pem, worker_key)
    try:
        evidence = _health_evidence(worker_key)
        health_status, health_response = server.post("/api/v1/internal/workers/health", {
            "worker_id": evidence.worker_id,
            "status": evidence.status,
            "observed_at": evidence.observed_at.isoformat(),
            "sequence": evidence.sequence,
            "nonce": evidence.nonce,
            "signature_b64url": evidence.signature_b64url,
        })
        assert health_status == 200
        assert health_response["status"] == "HEALTHY"

        ticket_path = f"/api/v1/internal/workers/worker-test-01/sessions/{session_id}/ticket"
        request_body = {"session_id": session_id}
        headers = {"Delivery-Id": "local-tls-delivery-retry-0001"}
        first_status, first = server.post(ticket_path, request_body, headers=headers)
        retry_status, retry = server.post(ticket_path, request_body, headers=headers)
        assert first_status == retry_status == 200
        assert first["ticket"] == retry["ticket"]

        redeem_path = f"/api/v1/internal/workers/worker-test-01/sessions/{session_id}/redeem"
        redeem_status, redeemed = server.post(redeem_path, {"ticket": first["ticket"]})
        assert redeem_status == 200
        assert redeemed == {"authorized": True, "session_id": session_id, "runtime_started": False}
        replay_status, replay_body = server.post(redeem_path, {"ticket": first["ticket"]})
        assert replay_status == 409
        assert first["ticket"] not in json.dumps(replay_body)
    finally:
        server.close()
