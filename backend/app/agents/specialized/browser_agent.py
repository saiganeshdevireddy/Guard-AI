"""
Specialized Browser Security Agent & Isolated Browsing Inspector.

Inspects web destinations, validates HTTP security headers, sanitizes DOM structures,
and flags insecure script vectors for the isolated sandbox viewer.
Explicitly acknowledges that sandboxing mitigates risks but cannot guarantee 100% protection.
"""
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from app.agents.base import BaseAgent, event_bus


class BrowserSecurityAgent(BaseAgent):
    """Specialized agent for web security headers, cookie policies, and isolated preview safety."""

    def __init__(self):
        super().__init__(
            agent_id="agent_browser_security",
            name="Browser Security Agent",
            role="Inspects web destination headers, script vectors, and enforces safe isolated preview"
        )

    def _register_event_handlers(self):
        event_bus.subscribe("INSPECT_URL_HEADERS", self._on_inspect_request)

    def _on_inspect_request(self, event):
        url = event.payload.get("url")
        if url:
            result = self.inspect_destination(url)
            self.emit_event("BROWSER_INSPECTION_COMPLETED", {"url": url, "result": result})

    def sanitize_html_for_sandbox(self, raw_html: str) -> str:
        """
        Strips executable script tags, event handlers, and active payloads
        to allow safe visual inspection inside an isolated sandboxed iframe.
        """
        # 1. Strip <script>...</script>
        clean = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '<!-- [Script Blocked by Guard AI Sandbox] -->', raw_html, flags=re.IGNORECASE)
        # 2. Strip inline event handlers like onclick, onerror, onload
        clean = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', ' data-blocked-handler="true"', clean, flags=re.IGNORECASE)
        # 3. Strip javascript: pseudo-protocol URIs
        clean = re.sub(r'href\s*=\s*["\']javascript:[^"\']*["\']', 'href="#blocked-by-guard-ai"', clean, flags=re.IGNORECASE)
        # 4. Strip <object>, <embed>, <applet>
        clean = re.sub(r'<(object|embed|applet)\b[^<]*(?:(?!<\/\1>)<[^<]*)*<\/\1>', '<!-- [Active Object Blocked] -->', clean, flags=re.IGNORECASE)
        return clean

    def inspect_destination(self, url: str, mock_headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Evaluates security headers and connection posture for a URL.
        """
        self.task_count += 1
        self.heartbeat()

        parsed = urlparse(url)
        is_https = parsed.scheme.lower() == "https"
        headers = {k.lower(): v for k, v in (mock_headers or {}).items()}

        warnings: List[str] = []
        score = 100  # Start with perfect score and deduct for deficiencies

        if not is_https:
            score -= 40
            warnings.append("Connection is not encrypted (HTTP plain-text). Data in transit is vulnerable to interception.")

        # Check essential security headers
        if "content-security-policy" not in headers:
            score -= 15
            warnings.append("Missing 'Content-Security-Policy' (CSP) header: Greater risk of Cross-Site Scripting (XSS).")
        if "strict-transport-security" not in headers and is_https:
            score -= 10
            warnings.append("Missing HSTS header: Vulnerable to SSL-stripping downgrade attacks.")
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            score -= 10
            warnings.append("Missing clickjacking protection ('X-Frame-Options' or 'frame-ancestors').")
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            score -= 10
            warnings.append("Missing or invalid 'X-Content-Type-Options: nosniff' header.")

        final_score = max(score, 0)
        safety_status = "SECURE"
        if final_score < 50:
            safety_status = "CRITICAL_RISK"
        elif final_score < 75:
            safety_status = "MODERATE_RISK"

        result = {
            "url": url,
            "is_https": is_https,
            "security_score": final_score,
            "safety_status": safety_status,
            "warnings": warnings if warnings else ["All fundamental browser security headers are enforced."],
            "sandbox_ready": True,
            "disclaimer": "Isolated browsing mitigates malware exposure, but does not guarantee absolute immunity against zero-day browser vulnerabilities."
        }
        self.metrics["last_inspection"] = result
        return result

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        url = message.get("url", "")
        headers = message.get("headers", {})
        return self.inspect_destination(url, headers)
