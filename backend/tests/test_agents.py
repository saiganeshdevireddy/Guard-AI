"""
Automated unit and integration tests for all Guard AI agents.
"""
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
    assert any("bare IP" in ind for ind in ip_host["indicators"])


def test_file_agent_detection():
    agent = FileSecurityAgent()
    # 1. Benign text
    clean_bytes = b"Hello, this is a normal benign text file."
    res = agent.analyze_bytes(clean_bytes, "notes.txt")
    assert res["classification"] == "CLEAN"
    assert res["entropy"] < 5.0

    # 2. Ransomware volume shadow deletion heuristic
    ransom_bytes = b"echo Starting process && vssadmin delete shadows /all /quiet"
    res_ransom = agent.analyze_bytes(ransom_bytes, "script.bat")
    assert res_ransom["score"] >= 50
    assert any("Volume Shadow Copy Deletion" in r for r in res_ransom["matched_rules"])

    # 3. Disguised executable (PE header with .png extension)
    fake_png = b"MZ" + b"\x00" * 200
    res_disguised = agent.analyze_bytes(fake_png, "photo.png")
    assert res_disguised["score"] >= 70
    assert any("File Masquerading" in ind for ind in res_disguised["indicators"])


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
