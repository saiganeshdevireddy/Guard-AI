"""
Finder AI - Unified Threat Discovery & Investigation Agent.

Coordinates specialized detection modules:
- URL & Phishing analysis
- File integrity & malware heuristics
- Wi-Fi & network telemetry
- Spam & fraudulent message evaluation
Reports all discovered threats directly to Controller AI.
"""
from typing import Any, Dict, List, Optional
from app.agents.base import BaseAgent, event_bus
from app.agents.specialized.phishing_agent import PhishingDetectionAgent
from app.agents.specialized.file_agent import FileSecurityAgent
from app.agents.specialized.wifi_agent import WifiSecurityAgent
from app.agents.specialized.browser_agent import BrowserSecurityAgent
from app.agents.specialized.spam_agent import SpamDetectionAgent


class FinderAI(BaseAgent):
    """
    Central discovery agent responsible for identifying threat vectors across
    URLs, files, network profiles, and incoming communications.
    """

    def __init__(self):
        super().__init__(
            agent_id="finder_ai",
            name="Finder AI",
            role="Detects, analyzes, and classifies threats across URLs, files, network, and communications"
        )
        # Instantiate sub-agents
        self.phishing_agent = PhishingDetectionAgent()
        self.file_agent = FileSecurityAgent()
        self.wifi_agent = WifiSecurityAgent()
        self.browser_agent = BrowserSecurityAgent()
        self.spam_agent = SpamDetectionAgent()

    def _register_event_handlers(self):
        # Listen for trigger requests from Controller AI or API
        event_bus.subscribe("FINDER_SCAN_URL", self._on_scan_url)
        event_bus.subscribe("FINDER_SCAN_FILE", self._on_scan_file)
        event_bus.subscribe("FINDER_SCAN_NETWORK", self._on_scan_network)
        event_bus.subscribe("FINDER_SCAN_TEXT", self._on_scan_text)

    def _on_scan_url(self, event):
        url = event.payload.get("url")
        if url:
            self.scan_url(url)

    def _on_scan_file(self, event):
        filepath = event.payload.get("filepath")
        if filepath:
            self.scan_file_path(filepath)

    def _on_scan_network(self, event):
        self.scan_network(event.payload)

    def _on_scan_text(self, event):
        text = event.payload.get("text", "")
        self.scan_text(text)

    def scan_url(self, url: str) -> Dict[str, Any]:
        """Runs URL through Phishing and Browser inspection."""
        self.task_count += 1
        self.heartbeat()

        phishing_res = self.phishing_agent.analyze_url(url)
        browser_res = self.browser_agent.inspect_destination(url)

        # Header posture is only scored when real response headers were supplied.
        # The local URL scan does not fetch remote pages, so default headers must
        # never be treated as evidence that a destination is insecure or safe.
        browser_score = (
            100 - browser_res["security_score"]
            if browser_res.get("headers_available") and browser_res.get("security_score") is not None
            else 0
        )
        max_score = max(phishing_res["score"], browser_score)
        severity = "LOW"
        if max_score >= 80:
            severity = "CRITICAL"
        elif max_score >= 60:
            severity = "HIGH"
        elif max_score >= 35:
            severity = "MEDIUM"

        composite_report = {
            "target": url,
            "type": "URL",
            "composite_score": max_score,
            "severity": severity,
            "phishing_analysis": phishing_res,
            "browser_analysis": browser_res,
            "all_indicators": phishing_res["indicators"] + browser_res["warnings"]
        }

        # Dispatch findings to Controller AI
        self.emit_event(
            event_type="THREAT_REPORT_SUBMITTED",
            payload={
                "source": "Finder AI",
                "category": "URL",
                "indicator": url,
                "severity": severity,
                "score": max_score,
                "details": composite_report,
                "description": f"URL scan completed for '{url}'. Composite threat rating: {severity} ({max_score}/100)."
            },
            severity=severity
        )
        return composite_report

    def scan_file_bytes(self, content: bytes, filename: str) -> Dict[str, Any]:
        """Runs byte content through FileSecurityAgent."""
        self.task_count += 1
        self.heartbeat()

        file_res = self.file_agent.analyze_bytes(content, filename)
        score = file_res["score"]
        severity = "LOW"
        if score >= 75:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"

        report = {
            "target": filename,
            "type": "FILE",
            "composite_score": score,
            "severity": severity,
            "file_analysis": file_res,
            "all_indicators": file_res["indicators"]
        }

        self.emit_event(
            event_type="THREAT_REPORT_SUBMITTED",
            payload={
                "source": "Finder AI",
                "category": "FILE",
                "indicator": file_res["sha256"],
                "severity": severity,
                "score": score,
                "details": report,
                "description": f"File scan completed for '{filename}'. SHA-256: {file_res['sha256'][:16]}... Rating: {severity}."
            },
            severity=severity
        )
        return report

    def scan_network(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Runs wireless parameters through WifiSecurityAgent."""
        self.task_count += 1
        self.heartbeat()

        wifi_res = self.wifi_agent.analyze_network(network_data)
        severity = wifi_res["risk_level"]

        report = {
            "target": network_data.get("ssid", "Unknown Network"),
            "type": "NETWORK",
            "composite_score": wifi_res["risk_score"],
            "severity": severity,
            "wifi_analysis": wifi_res,
            "all_indicators": wifi_res["vulnerabilities"]
        }

        self.emit_event(
            event_type="THREAT_REPORT_SUBMITTED",
            payload={
                "source": "Finder AI",
                "category": "NETWORK",
                "indicator": network_data.get("ssid", "Unknown Network"),
                "severity": severity,
                "score": wifi_res["risk_score"],
                "details": report,
                "description": f"Wireless scan completed for '{network_data.get('ssid')}'. Security posture: {severity}."
            },
            severity=severity
        )
        return report

    def scan_text(self, text: str) -> Dict[str, Any]:
        """Runs message text through SpamDetectionAgent."""
        self.task_count += 1
        self.heartbeat()

        spam_res = self.spam_agent.analyze_text(text)
        score = spam_res["score"]
        severity = "LOW"
        if score >= 70:
            severity = "CRITICAL"
        elif score >= 45:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"

        report = {
            "target": text[:60] + ("..." if len(text) > 60 else ""),
            "type": "SPAM_MESSAGE",
            "composite_score": score,
            "severity": severity,
            "spam_analysis": spam_res,
            "all_indicators": [t["explanation"] for t in spam_res["triggers"]]
        }

        self.emit_event(
            event_type="THREAT_REPORT_SUBMITTED",
            payload={
                "source": "Finder AI",
                "category": "SPAM",
                "indicator": text[:40],
                "severity": severity,
                "score": score,
                "details": report,
                "description": f"Message text analyzed. Threat rating: {severity} ({score}/100)."
            },
            severity=severity
        )
        return report

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        action = message.get("action")
        if action == "scan_url":
            return self.scan_url(message.get("url", ""))
        elif action == "scan_text":
            return self.scan_text(message.get("text", ""))
        elif action == "scan_network":
            return self.scan_network(message.get("network_data", {}))
        return {"error": f"Unknown action '{action}' for Finder AI"}
