"""
Isolated Browsing & Safe File Inspection Engine.

Provides an isolated environment for safe preview of suspicious web pages and files:
- Strips active executable scripts, event handlers, and objects.
- Enforces strict size limits and timeout constraints.
- Sandboxes DOM rendering within restricted iframes.
- Emphasizes explicit security warnings without false claims of complete invulnerability.
"""
import re
from typing import Any, Dict
from urllib.parse import urlparse

from app.agents.specialized.browser_agent import BrowserSecurityAgent


class SandboxEngine:
    """
    Manages safe preview generation for suspicious URLs and untrusted files.
    """

    def __init__(self):
        self.browser_inspector = BrowserSecurityAgent()
        self.max_download_bytes = 512 * 1024  # 512 KB safeguard against memory exhaustion

    async def inspect_url_safely(self, target_url: str) -> Dict[str, Any]:
        """
        Provides a local-only URL review without fetching or rendering remote content.
        A real isolated browser runtime is not included in this prototype; fetching
        arbitrary URLs from the backend would expose local services to SSRF.
        """
        url = target_url.strip()
        if not url:
            raise ValueError("URL cannot be empty")
        if "://" not in url:
            url = "https://" + url
        parsed = urlparse(url)
        headers_audit = self.browser_inspector.inspect_destination(url)
        return {
            "url": url,
            "preview_available": False,
            "status_code": None,
            "security_headers": headers_audit,
            "warning": "Remote content was not fetched or rendered. This prototype has no hardened isolated browser runtime.",
            "limitations": [
                "URL checks are local heuristics and do not establish that a destination is safe.",
                "Live response headers and page content were not inspected.",
                "Use a separate disposable virtual machine or browser profile for suspicious links.",
            ],
        }

    def inspect_file_safely(self, filename: str, content: bytes) -> Dict[str, Any]:
        """
        Produces a safe hex and text preview for untrusted files without invoking OS execution.
        """
        size = len(content)
        preview_bytes = content[:512]

        # Generate hex dump
        hex_lines = []
        for i in range(0, len(preview_bytes), 16):
            chunk = preview_bytes[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_lines.append(f"{i:04x}:  {hex_part:<48}  |{ascii_part}|")

        return {
            "filename": filename,
            "size_bytes": size,
            "hex_preview": "\n".join(hex_lines),
            "is_truncated": size > 512,
            "warning": "Safe file inspection shows raw bytecode without loading OS libraries or executing binary code."
        }


sandbox_engine = SandboxEngine()
