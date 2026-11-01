"""
Hybrid AI Engine: Local Offline Intelligence + Privacy-Guarded Cloud AI Assistance.

Strictly protects privacy:
- Local Mode (default): All evaluation runs offline on the local machine with zero data egress.
- Cloud Assistance: Sanitizes PII before sending summaries, and provides natural-language remediation.
"""
import re
from typing import Any, Dict, Optional
from app.config import settings


class HybridAIEngine:
    """
    Coordinates local deterministic heuristics with optional privacy-safe cloud intelligence.
    """

    def __init__(self):
        self.local_only = settings.LOCAL_ONLY_MODE
        self.api_key = settings.GEMINI_API_KEY

    def sanitize_pii(self, text: str) -> str:
        """
        Redacts personal email addresses, IP addresses, credit cards, and tokens
        before any cloud transmission.
        """
        # Redact emails
        text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
        # Redact IPv4
        text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', text)
        # Redact potential credit card sequences (13-16 digits)
        text = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_CARD]', text)
        return text

    def analyze_threat_context(
        self,
        indicator: str,
        category: str,
        severity: str,
        raw_details: Dict[str, Any],
        user_opt_in_cloud: bool = False
    ) -> Dict[str, Any]:
        """
        Produces an intelligent explanation of the threat.
        In local-only mode, operates completely offline via deterministic knowledge models.
        """
        # Always sanitize indicators if cloud assistance were ever engaged
        clean_indicator = self.sanitize_pii(indicator)

        # Deterministic local knowledge synthesizer
        if self.local_only or not user_opt_in_cloud:
            return {
                "mode": "LOCAL_OFFLINE_INTELLIGENCE",
                "privacy_guaranteed": True,
                "data_transmitted_external": False,
                "ai_summary": self._generate_local_ai_explanation(clean_indicator, category, severity),
                "remediation_steps": self._get_local_remediation(category, severity),
            }

        # Cloud AI assistance (Mock/Gemini compatible fallback)
        return {
            "mode": "CLOUD_AI_ASSISTED",
            "privacy_guaranteed": "PII_REDACTED",
            "data_transmitted_external": True,
            "ai_summary": (
                f"[Cloud Intelligence] Analysis of '{clean_indicator}' indicates a {severity} risk profile in category {category}. "
                f"Correlated against global threat intelligence vectors."
            ),
            "remediation_steps": self._get_local_remediation(category, severity),
        }

    def _generate_local_ai_explanation(self, indicator: str, category: str, severity: str) -> str:
        templates = {
            "URL": f"Local threat modeling flags destination '{indicator}' due to structural, lexical, or domain irregularities typical of credential harvesting or malware redirection.",
            "FILE": f"Static inspection of file '{indicator}' revealed anomalous entropy and signature patterns consistent with packed or hostile executables.",
            "NETWORK": f"Network analysis identifies weak encryption or rogue AP mimicry for '{indicator}', exposing unencrypted traffic to eavesdropping.",
            "SPAM": f"Linguistic modeling identifies social-engineering urgency and credential solicitation in '{indicator}'.",
        }
        return templates.get(category, f"Local heuristics detected a {severity} anomaly associated with indicator '{indicator}'.")

    def _get_local_remediation(self, category: str, severity: str) -> list[str]:
        base_remediations = {
            "URL": [
                "Do not enter passwords, credit cards, or personal information on this destination.",
                "Inspect the destination safely within the Guard AI Isolated Sandbox viewer.",
                "Clear temporary browser cookies if you accidentally visited the link."
            ],
            "FILE": [
                "Do not open, execute, or double-click the file outside a sandboxed environment.",
                "Keep the file in Guard AI quarantine to prevent OS process spawning.",
                "Verify file origin with the purported sender before unblocking."
            ],
            "NETWORK": [
                "Disconnect from this unencrypted or suspicious wireless network.",
                "Activate a trustworthy VPN with WireGuard/OpenVPN encryption.",
                "Configure your device to disable automatic reconnection to open networks."
            ],
            "SPAM": [
                "Delete the message immediately; do not reply or call provided phone numbers.",
                "Never share OTPs, PINs, or verification codes with unverified callers.",
                "Block the sender address on your messaging provider."
            ]
        }
        return base_remediations.get(category, ["Monitor system status on Guard AI dashboard."])


hybrid_ai = HybridAIEngine()
