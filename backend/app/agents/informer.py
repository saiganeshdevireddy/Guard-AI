"""
Informer AI - Voice-Enabled Security Communications & Plain-Language Explanations.

Transforms technical threat indicators into clear, actionable, spoken briefings.
Strict mandate: Communicates solely with the authorized user and never auto-reports
incidents to external authorities without explicit consent.
"""
from typing import Any, Dict, List, Optional
from app.agents.base import BaseAgent, event_bus


class InformerAI(BaseAgent):
    """
    Communicator agent translating cryptographic and threat signals into
    voice alerts, human-friendly guidance, and status summaries.
    """

    def __init__(self):
        super().__init__(
            agent_id="informer_ai",
            name="Informer AI",
            role="Voice-based security notifications, plain-language explanations, and incident briefings"
        )
        self.latest_briefing: Optional[Dict[str, Any]] = None

    def _register_event_handlers(self):
        event_bus.subscribe("THREAT_REPORT_SUBMITTED", self._on_threat_report)
        event_bus.subscribe("EMERGENCY_LOCKDOWN_ACTIVATED", self._on_emergency)
        event_bus.subscribe("VAULT_LOCKED", self._on_vault_locked)

    def _on_threat_report(self, event):
        payload = event.payload
        severity = payload.get("severity", "INFO")
        if severity in ["MEDIUM", "HIGH", "CRITICAL"]:
            briefing = self.generate_threat_briefing(payload)
            self.emit_event(
                event_type="VOICE_BRIEFING_READY",
                payload={"briefing": briefing},
                severity=severity
            )

    def _on_emergency(self, event):
        level = event.payload.get("level", "HEIGHTENED")
        speech_text = f"Security alert: Emergency lockdown level {level} is now active. All sensitive vaults are sealed."
        briefing = {
            "title": "Emergency Lockdown Active",
            "spoken_text": speech_text,
            "plain_explanation": "Defensive containment has been engaged to prevent potential unauthorized access.",
            "recommendation": "Review active incidents on your dashboard before resetting containment.",
            "urgency": "CRITICAL"
        }
        self.latest_briefing = briefing
        self.emit_event("VOICE_BRIEFING_READY", {"briefing": briefing}, severity="CRITICAL")

    def _on_vault_locked(self, event):
        speech_text = "Notice: The Cryptographic Vault has been securely sealed."
        self.emit_event("VOICE_BRIEFING_READY", {
            "briefing": {
                "title": "Vault Locked",
                "spoken_text": speech_text,
                "plain_explanation": "Memory keys have been cleared to protect your sensitive credentials.",
                "recommendation": "Enter your master passphrase when you need to access encrypted items.",
                "urgency": "INFO"
            }
        })

    def generate_threat_briefing(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Creates a structured, 3-part plain-language briefing:
        1. What was detected
        2. Potential impact
        3. Actionable next step
        """
        self.task_count += 1
        self.heartbeat()

        category = threat_data.get("category", "GENERAL")
        severity = threat_data.get("severity", "LOW")
        indicator = threat_data.get("indicator", "item")

        if category == "URL" or category == "PHISHING":
            spoken = (
                f"Warning: A suspicious link has been detected. The destination appears to impersonate a legitimate service "
                f"and may attempt to harvest your credentials. We recommend avoiding this page."
            )
            what = f"Finder AI identified phishing indicators in the link '{indicator}'."
            impact = "Visiting this site could trick you into entering passwords or downloading malicious files."
            action = "Close the browser tab. Guard AI has quarantined the link from automatic opening."

        elif category == "FILE":
            spoken = (
                f"Caution: A file has been flagged with a threat severity of {severity}. "
                f"Static analysis detected suspicious code execution patterns."
            )
            what = f"File inspection detected anomalous entropy or malicious heuristics."
            impact = "Opening this file could allow unauthorized scripts to execute on your machine."
            action = "Keep this file in quarantine or inspect it in the isolated Guard AI sandbox before opening."

        elif category == "NETWORK":
            spoken = (
                f"Network notification: The Wi-Fi network '{indicator}' has security vulnerabilities. "
                f"Unencrypted communications may be visible to attackers."
            )
            what = f"Wi-Fi network '{indicator}' is using weak or no encryption."
            impact = "Anyone connected to the same wireless access point could intercept your unencrypted internet traffic."
            action = "Connect to a trusted private network or activate a VPN immediately."

        elif category == "SPAM":
            spoken = (
                f"Communication notice: Message contains deceptive financial or urgent extortion phrases."
            )
            what = "The message uses urgency tactics and requests for sensitive credentials."
            impact = "Complying with the request could result in financial fraud or account takeover."
            action = "Do not reply, click embedded links, or transfer money or codes."

        else:
            spoken = f"Guard AI alert: {threat_data.get('description', 'A security event requires your attention.')}"
            what = threat_data.get("description", "Unusual activity detected.")
            impact = "May indicate anomalous application or network behavior."
            action = "Review the event log on your Guard AI dashboard."

        briefing = {
            "title": f"{severity} Threat Alert: {category}",
            "spoken_text": spoken,
            "plain_explanation": what,
            "impact_summary": impact,
            "recommended_action": action,
            "urgency": severity,
            "category": category,
            "indicator": indicator
        }
        self.latest_briefing = briefing
        return briefing

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        action = message.get("action")
        if action == "briefing":
            return self.latest_briefing or {
                "title": "System Secure",
                "spoken_text": "Guard AI multi-agent defence is active and operating normally.",
                "plain_explanation": "All detection agents report healthy baseline telemetry.",
                "impact_summary": "Your device and vault are actively protected.",
                "recommended_action": "No action required.",
                "urgency": "INFO"
            }
        return {"error": f"Unknown action '{action}' for Informer AI"}
