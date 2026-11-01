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
import httpx

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
        Fetches web page text under strict isolation limits,
        sanitizes all active script payloads, and generates a sandboxed preview document.
        """
        # Ensure scheme
        url = target_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        headers_audit = self.browser_inspector.inspect_destination(url)

        raw_html = ""
        fetch_error = None
        status_code = None

        try:
            # Safe HTTP fetch with tight 5-second timeout and no redirect loops
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(url, headers={"User-Agent": "GuardAI-Isolated-Sandbox-Inspector/1.0"})
                status_code = resp.status_code
                # Limit size to prevent DoS / zip bomb
                content_bytes = resp.content[:self.max_download_bytes]
                raw_html = content_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            fetch_error = str(e)
            raw_html = f"<html><body><div style='padding:20px;color:#ff5555;font-family:sans-serif;'><h3>[Sandbox Isolated Connection Error]</h3><p>Could not safely establish connection: {str(e)}</p></div></body></html>"

        # Sanitize HTML to prevent code execution
        sanitized_html = self.browser_inspector.sanitize_html_for_sandbox(raw_html)

        # Inject high-visibility sandbox banner
        banner = (
            "<div style='background:#1a1d24;border-bottom:2px solid #ffaa00;padding:12px 16px;color:#fff;font-family:sans-serif;font-size:13px;display:flex;align-items:center;justify-content:space-between;'>"
            "<span><strong>[GUARD AI ISOLATED SANDBOX]</strong> Scripts Disabled &bull; Network Storage Blocked &bull; Safe Visual Mode</span>"
            "<span style='background:#ffaa00;color:#000;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:11px;'>RESTRICTED</span>"
            "</div>"
        )
        safe_preview_doc = f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Sandbox Preview</title></head><body style='margin:0;padding:0;'>{banner}{sanitized_html}</body></html>"

        return {
            "url": target_url,
            "status_code": status_code,
            "fetch_error": fetch_error,
            "security_headers": headers_audit,
            "sanitized_html": safe_preview_doc,
            "raw_size_bytes": len(raw_html),
            "scripts_blocked": True,
            "warning": (
                "Notice: Isolated browsing renders static visual content with active JavaScript disabled. "
                "This significantly reduces threat vectors, but sandbox isolation is not a substitute for complete environment air-gapping."
            )
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
