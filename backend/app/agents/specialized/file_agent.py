"""
Specialized File Security Agent (Static Analysis, Entropy, Hashes & YARA-style Signatures).
"""
import hashlib
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.agents.base import BaseAgent, event_bus

KNOWN_MALICIOUS_HASHES = {
    # Sample real malware signatures (WannaCry, Emotet, Locky reference hashes)
    "ed01845102c51720d10fd4196fcee882ed68b4fb84d61ceb5736e0a34e4f9b45": "WannaCry Ransomware Dropper",
    "84c82835a5d21bbcf75a61706d8ab549": "Locky Ransomware Variant",
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": "Emotet Loader",
}

HEURISTIC_RULES = [
    {
        "id": "RULE_001_SHADOW_DELETE",
        "name": "Volume Shadow Copy Deletion (Ransomware)",
        "pattern": rb"(?i)vssadmin(\.exe)?\s+delete\s+shadows",
        "score": 50,
        "description": "Attempts to inhibit system recovery by deleting volume shadow copies",
    },
    {
        "id": "RULE_002_OBFUSCATED_POWERSHELL",
        "name": "Obfuscated / Hidden PowerShell Execution",
        "pattern": rb"(?i)powershell(\.exe)?\s+.*-(enc|encodedcommand|w\s+hidden|windowstyle\s+hidden)",
        "score": 40,
        "description": "Executes encoded or hidden PowerShell commands often used in fileless attacks",
    },
    {
        "id": "RULE_003_PERSISTENCE_REGISTRY",
        "name": "Registry Run Key Persistence",
        "pattern": rb"(?i)reg\s+add\s+.*\\CurrentVersion\\Run",
        "score": 35,
        "description": "Installs automated persistence in Windows startup registry keys",
    },
    {
        "id": "RULE_004_CERTUTIL_DOWNLOAD",
        "name": "Living-off-the-Land Binary (LOLBIN) Ingress",
        "pattern": rb"(?i)certutil(\.exe)?\s+.*-urlcache",
        "score": 35,
        "description": "Abuses native certutil utility to download external payloads",
    },
    {
        "id": "RULE_005_RANSOM_NOTE",
        "name": "Ransomware Extortion Strings",
        "pattern": rb"(?i)(your\s+files\s+have\s+been\s+encrypted|pay\s+bitcoin\s+to\s+decrypt|\.onion\s+address)",
        "score": 60,
        "description": "Contains explicit extortion language common to ransomware notes",
    },
]


def calculate_byte_entropy(data: bytes) -> float:
    """Calculates byte-level Shannon entropy (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


class FileSecurityAgent(BaseAgent):
    """Specialized agent for inspecting file integrity, entropy, and malicious signatures."""

    def __init__(self):
        super().__init__(
            agent_id="agent_file_security",
            name="File Security Agent",
            role="Performs static analysis, entropy calculation, and signature detection on files"
        )

    def _register_event_handlers(self):
        event_bus.subscribe("SCAN_FILE_REQUEST", self._on_file_scan_request)

    def _on_file_scan_request(self, event):
        filepath = event.payload.get("filepath")
        if filepath and os.path.exists(filepath):
            with open(filepath, "rb") as f:
                content = f.read()
            filename = Path(filepath).name
            result = self.analyze_bytes(content, filename)
            self.emit_event(
                event_type="FILE_ANALYSIS_COMPLETED",
                payload={"filename": filename, "result": result},
                severity="CRITICAL" if result["score"] >= 75 else ("HIGH" if result["score"] >= 50 else "INFO")
            )

    def analyze_bytes(self, content: bytes, filename: str = "uploaded_file") -> Dict[str, Any]:
        """
        Conducts static inspection of file bytes.
        """
        self.task_count += 1
        self.heartbeat()

        size_bytes = len(content)
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        entropy = calculate_byte_entropy(content)

        score = 0
        indicators: List[str] = []
        matched_rules: List[str] = []

        # 1. Exact hash signature match
        if sha256 in KNOWN_MALICIOUS_HASHES:
            score += 100
            indicators.append(f"Known malicious SHA-256 signature: {KNOWN_MALICIOUS_HASHES[sha256]}")
        elif md5 in KNOWN_MALICIOUS_HASHES:
            score += 100
            indicators.append(f"Known malicious MD5 signature: {KNOWN_MALICIOUS_HASHES[md5]}")

        # 2. Magic byte mismatch detection (e.g. .pdf or .png that is actually a Windows PE executable)
        is_pe = content.startswith(b"MZ")
        is_elf = content.startswith(b"\x7fELF")
        ext = Path(filename).suffix.lower()

        if is_pe:
            if ext in [".png", ".jpg", ".pdf", ".txt", ".docx", ".xlsx", ".mp3", ".mp4"]:
                score += 70
                indicators.append(f"File Masquerading: Windows PE executable header (MZ) disguised with extension '{ext}'")
            else:
                indicators.append("Windows PE executable detected (MZ header)")

        # 3. High entropy evaluation (packed, obfuscated, or encrypted ransomware payload)
        if entropy > 7.3 and size_bytes > 4096:
            score += 35
            indicators.append(f"Abnormally high entropy ({entropy:.2f} / 8.0) indicating heavy packing or encryption")
        elif entropy > 6.8:
            indicators.append(f"Elevated entropy ({entropy:.2f} / 8.0)")

        # 4. YARA-style heuristic rules matching
        for rule in HEURISTIC_RULES:
            if re.search(rule["pattern"], content):
                score += rule["score"]
                matched_rules.append(rule["name"])
                indicators.append(f"{rule['name']}: {rule['description']}")

        final_score = min(score, 100)
        classification = "CLEAN"
        if final_score >= 70:
            classification = "MALICIOUS"
        elif final_score >= 35:
            classification = "SUSPICIOUS"
        elif final_score > 0:
            classification = "LOW_RISK"

        result = {
            "filename": filename,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "md5": md5,
            "entropy": round(entropy, 2),
            "is_executable": is_pe or is_elf,
            "score": final_score,
            "classification": classification,
            "matched_rules": matched_rules,
            "indicators": indicators if indicators else ["No known malicious patterns or abnormal entropy detected"],
        }
        self.metrics["last_scan"] = result
        return result

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        data = message.get("content")
        if data is None:
            return {"error": "Missing 'content' byte data"}
        filename = message.get("filename", "unknown.bin")
        if isinstance(data, str):
            content = data.encode("utf-8")
        else:
            content = bytes(data)
        return self.analyze_bytes(content, filename)
