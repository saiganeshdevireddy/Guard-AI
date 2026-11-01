"""
Specialized Spam and Scam Detection Agent.

Evaluates messages, emails, SMS, and prompt payloads for financial fraud,
urgent extortion, tech-support scams, and credential harvesting patterns.
"""
import re
from typing import Any, Dict, List
from app.agents.base import BaseAgent, event_bus

SCAM_TRIGGERS = [
    {
        "category": "FINANCIAL_FRAUD",
        "pattern": r"(?i)(send\s+crypto|send\s+bitcoin|wire\s+transfer|gift\s+card|inheritance\s+fund|lottery\s+winner|million\s+dollars|claim\s+your\s+prize)",
        "weight": 35,
        "detail": "Prompts advance-fee wire, cryptocurrency, or gift-card payment"
    },
    {
        "category": "ARTIFICIAL_URGENCY",
        "pattern": r"(?i)(act\s+now|within\s+24\s+hours|account\s+will\s+be\s+suspended|immediate\s+action\s+required|urgent|last\s+warning)",
        "weight": 30,
        "detail": "Leverages artificial urgency to bypass critical reasoning"
    },
    {
        "category": "CREDENTIAL_HARVESTING",
        "pattern": r"(?i)(provide\s+your\s+password|send\s+otp|enter\s+your\s+pin|verify\s+your\s+ssn|bank\s+account\s+details)",
        "weight": 40,
        "detail": "Explicitly requests secret credentials, OTP, or identity tokens"
    },
    {
        "category": "FAKE_TECH_SUPPORT",
        "pattern": r"(?i)(call\s+toll-free|microsoft\s+support\s+number|apple\s+security\s+hotline|critical\s+virus\s+detected\s+call)",
        "weight": 35,
        "detail": "Impersonates technical support hotline"
    },
    {
        "category": "SUSPICIOUS_LINKS",
        "pattern": r"(?i)(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\/[a-zA-Z0-9]+",
        "weight": 20,
        "detail": "Uses shortened URL to conceal final destination"
    }
]


class SpamDetectionAgent(BaseAgent):
    """Specialized agent for linguistic analysis of spam, scams, and fraudulent messages."""

    def __init__(self):
        super().__init__(
            agent_id="agent_spam_detection",
            name="Spam & Scam Detection Agent",
            role="Detects social engineering, financial scam indicators, and phishing text"
        )

    def _register_event_handlers(self):
        event_bus.subscribe("ANALYZE_TEXT_REQUEST", self._on_text_request)

    def _on_text_request(self, event):
        text = event.payload.get("text", "")
        result = self.analyze_text(text)
        self.emit_event(
            event_type="SPAM_ANALYSIS_COMPLETED",
            payload={"result": result},
            severity="HIGH" if result["score"] >= 60 else "INFO"
        )

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Analyzes message text against fraudulent and social engineering patterns.
        """
        self.task_count += 1
        self.heartbeat()

        if not text or not text.strip():
            return {
                "score": 0,
                "classification": "CLEAN",
                "triggers": [],
                "summary": "Empty or neutral message"
            }

        score = 0
        triggers: List[Dict[str, str]] = []

        for rule in SCAM_TRIGGERS:
            matches = re.findall(rule["pattern"], text)
            if matches:
                score += rule["weight"]
                triggers.append({
                    "category": rule["category"],
                    "matched_phrases": list(set(matches))[:3],
                    "explanation": rule["detail"]
                })

        # Excessive uppercase check (emotional manipulation)
        letters = [c for c in text if c.isalpha()]
        if len(letters) > 20:
            upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
            if upper_ratio > 0.45:
                score += 15
                triggers.append({
                    "category": "EXCESSIVE_CAPITALIZATION",
                    "matched_phrases": ["HIGH_CAPS_RATIO"],
                    "explanation": f"Abnormal uppercase ratio ({int(upper_ratio*100)}%) designed to invoke panic"
                })

        final_score = min(score, 100)
        classification = "CLEAN"
        if final_score >= 70:
            classification = "SCAM_FRAUD"
        elif final_score >= 35:
            classification = "SUSPICIOUS_SPAM"
        elif final_score > 0:
            classification = "LOW_RISK"

        result = {
            "score": final_score,
            "classification": classification,
            "triggers": triggers,
            "summary": (
                f"Elevated scam probability ({final_score}/100) detected." if final_score >= 50
                else "Message appears benign with no obvious social engineering patterns."
            )
        }
        self.metrics["last_text_analysis"] = result
        return result

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        text = message.get("text", "")
        return self.analyze_text(text)
