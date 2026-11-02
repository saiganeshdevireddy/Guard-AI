"""
Automated unit and integration tests for all Guard AI agents.
"""
import os
import subprocess
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.agents.controller import ControllerAI
from app.agents.finder import FinderAI
from app.agents.informer import InformerAI
from app.agents.offence import OffenceAI
from app.agents.specialized.file_agent import FileSecurityAgent
from app.agents.specialized.phishing_agent import PhishingDetectionAgent
from app.agents.specialized.spam_agent import SpamDetectionAgent
from app.agents.specialized.wifi_agent import WifiSecurityAgent
from app.database import Base


def get_test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return TestingSession()


def test_phishing_agent_detection():
    agent = PhishingDetectionAgent()
    # 1. Legitimate URL
    clean = agent.analyze_url("https://www.google.com")
    assert clean["classification"] == "NO_KNOWN_INDICATORS"
    assert "does not establish" in clean["verdict_scope"]
    assert clean["score"] < 25

    # 2. Typosquatting of paypal
    typo = agent.analyze_url("http://paypa1.com/login-verify")
    assert typo["score"] >= 70
    assert "CRITICAL_PHISHING" in typo["classification"] or typo["score"] >= 70

    # 3. IP host with suspicious keywords
    ip_host = agent.analyze_url("http://192.168.1.50/account/login-update")
    assert ip_host["score"] >= 50
    assert any("non-public IP" in ind for ind in ip_host["indicators"])


def test_file_agent_detection():
    agent = FileSecurityAgent()
    # 1. Benign text
    clean_bytes = b"Hello, this is a normal benign text file."
    res = agent.analyze_bytes(clean_bytes, "notes.txt")
    assert res["classification"] == "NO_KNOWN_INDICATORS"
    assert res["entropy"] < 5.0

    # 2. Ransomware volume shadow deletion heuristic
    ransom_bytes = b"echo Starting process && vssadmin delete shadows /all /quiet"
    res_ransom = agent.analyze_bytes(ransom_bytes, "script.bat")
    assert res_ransom["score"] >= 50
    assert any("Volume Shadow Copy Deletion" in r for r in res_ransom["matched_rules"])

    # 3. Disguised executable (PE header with .png extension)
    fake_png = bytearray(b"MZ" + b"\x00" * 200)
    fake_png[0x3C:0x40] = (0x80).to_bytes(4, "little")
    fake_png[0x80:0x84] = b"PE\x00\x00"
    res_disguised = agent.analyze_bytes(bytes(fake_png), "photo.png")
    assert res_disguised["score"] >= 70
    assert any("signature (Windows PE executable) conflicts" in ind for ind in res_disguised["indicators"])


def test_url_analysis_redirects_false_positives_and_malformed_inputs():
    agent = PhishingDetectionAgent()
    ordinary = agent.analyze_url("https://example.com/news")
    assert ordinary["score"] == 0
    assert ordinary["redirect_targets_observed"] == []
    assert ordinary["fetch_performed"] is False

    # A brand substring inside a larger label is not itself proof of spoofing.
    brand_substring = agent.analyze_url("https://notpaypal.com/")
    assert not any("Brand-like" in finding for finding in brand_substring["indicators"])

    redirect = agent.analyze_url("https://example.com/?next=https%3A%2F%2Fevil.test%2Flogin")
    assert redirect["score"] >= 20
    assert redirect["redirect_targets_observed"] == ["evil.test"]
    assert "not proof of an actual redirect" in redirect["indicators"][-1]
    assert redirect["fetch_performed"] is False

    # A representative false-negative-shaped fixture remains unknown by policy.
    false_negative_fixture = agent.analyze_url("https://attacker.example/content")
    assert false_negative_fixture["score"] == 0
    assert "does not establish" in false_negative_fixture["verdict_scope"]

    for malformed in (
        "https://user:pass@example.com/", "https://bad host.test/", "https://example.com:bad/",
        "https://example.com/\x00path", "x" * 2049,
    ):
        assert agent.analyze_url(malformed)["classification"] == "MALFORMED_URL"

    excessive_fields = "https://example.com/?" + "&".join(f"k{i}=v" for i in range(101))
    bounded = agent.analyze_url(excessive_fields)
    assert any("bounded" in finding for finding in bounded["indicators"])


def test_file_signature_verification_and_optional_yara_failures(monkeypatch):
    from app.agents.specialized import file_agent

    agent = FileSecurityAgent()
    fake_mz = agent.analyze_bytes(b"MZ" + b"\x00" * 200, "fake.exe")
    assert fake_mz["detected_file_type"] == "Unknown / unsupported format"
    assert fake_mz["is_executable"] is False

    valid_png = agent.analyze_bytes(b"\x89PNG\r\n\x1a\n" + b"x", "image.png")
    assert valid_png["file_type_verified"] is True
    disguised_png = agent.analyze_bytes(b"%PDF-1.7", "image.png")
    assert disguised_png["file_type_verified"] is False
    assert disguised_png["score"] >= 35

    office_container = agent.analyze_bytes(b"PK\x03\x04minimal", "claimed.docx")
    assert office_container["file_type_status"] == "UNVERIFIED"
    assert any("contents were not validated" in finding for finding in office_container["indicators"])

    monkeypatch.setattr(file_agent.settings, "CLAMSCAN_PATH", "")
    monkeypatch.setattr(file_agent.settings, "YARA_PATH", "yara-test")
    monkeypatch.setattr(file_agent.settings, "YARA_RULES_PATH", "rules-test")
    observed = {}

    def yara_match(command, **kwargs):
        observed["shell"] = kwargs["shell"]
        observed["temp_path"] = command[-1]
        return SimpleNamespace(returncode=0, stdout="TEST_RULE match", stderr="")

    monkeypatch.setattr(file_agent.subprocess, "run", yara_match)
    result = agent.analyze_bytes(b"harmless test bytes", "sample.bin")
    assert result["classification"] == "SUSPICIOUS"
    assert result["optional_scanners"][0]["status"] == "RULE_MATCH"
    assert observed["shell"] is False
    assert "TEST_RULE match" not in str(result)
    assert not os.path.exists(observed["temp_path"])

    def yara_timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("yara-test", 8)

    monkeypatch.setattr(file_agent.subprocess, "run", yara_timeout)
    timed_out = agent.analyze_bytes(b"harmless test bytes", "sample.bin")
    assert timed_out["optional_scanners"][0]["status"] == "ERROR"

    monkeypatch.setattr(file_agent.subprocess, "run", yara_match)
    original_unlink = os.unlink
    cleanup_paths = []

    def unlink_failure(path):
        cleanup_paths.append(path)
        raise PermissionError("test cleanup failure")

    monkeypatch.setattr(file_agent.os, "unlink", unlink_failure)
    cleanup_failed = agent.analyze_bytes(b"harmless test bytes", "sample.bin")
    assert cleanup_failed["optional_scanners"][-1]["status"] == "FAILED"
    assert any("cleanup failed" in finding.lower() for finding in cleanup_failed["indicators"])
    monkeypatch.setattr(file_agent.os, "unlink", original_unlink)
    for path in cleanup_paths:
        if os.path.exists(path):
            os.unlink(path)


def test_wifi_agent_security_audit():
    agent = WifiSecurityAgent()
    # 1. Open unencrypted network
    open_net = agent.analyze_network({"ssid": "FreeCoffeeWifi", "security_type": "OPEN"})
    assert open_net["risk_level"] in ["HIGH", "CRITICAL"]
    assert any("unencrypted" in v.lower() for v in open_net["vulnerabilities"])

    # 2. Rogue AP / Evil twin indicator
    twin_net = agent.analyze_network({
        "ssid": "HomeNetwork",
        "security_type": "WPA2_PSK",
        "duplicate_ssids_detected": 2
    })
    assert twin_net["risk_score"] >= 40
    assert any("Evil Twin" in v for v in twin_net["vulnerabilities"])


def test_spam_agent_detection():
    agent = SpamDetectionAgent()
    clean_text = "Hey team, the project status meeting is at 2 PM today."
    res_clean = agent.analyze_text(clean_text)
    assert res_clean["classification"] == "CLEAN"

    scam_text = "URGENT: YOUR ACCOUNT WILL BE SUSPENDED IN 24 HOURS! SEND BITCOIN WIRE TRANSFER OR 500 GIFT CARD TO VERIFY YOUR SSN."
    res_scam = agent.analyze_text(scam_text)
    assert res_scam["score"] >= 65
    assert any(t["category"] in ["FINANCIAL_FRAUD", "ARTIFICIAL_URGENCY", "CREDENTIAL_HARVESTING"] for t in res_scam["triggers"])


def test_controller_threat_orchestration():
    db = get_test_db()
    controller = ControllerAI()

    # Simulate reporting a critical threat
    threat = controller.process_threat_report(
        db=db,
        report_data={
            "source": "Finder AI",
            "category": "URL",
            "indicator": "http://evil-banking-update.xyz/login",
            "score": 90,
            "description": "High-confidence credential harvester detected."
        }
    )

    assert threat.id is not None
    assert threat.severity == "CRITICAL"
    # Verify Defence vault was auto-locked
    assert controller.defence.is_vault_locked is True
    # Critical detections do not self-approve a high-impact emergency action.
    assert controller.offence.lockdown_level == "STANDARD"
    assert threat.status == "AWAITING_OPERATOR_REVIEW"


def test_informer_voice_briefing():
    informer = InformerAI()
    briefing = informer.generate_threat_briefing({
        "category": "PHISHING",
        "severity": "CRITICAL",
        "indicator": "http://phish-secure.xyz"
    })

    assert "Warning" in briefing["spoken_text"]
    assert briefing["urgency"] == "CRITICAL"
    assert "recommendation" in briefing or "recommended_action" in briefing
