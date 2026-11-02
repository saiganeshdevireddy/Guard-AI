"""
Specialized File Security Agent (Static Analysis, Entropy, Hashes & YARA-style Signatures).
"""
import hashlib
import math
import os
import re
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from app.agents.base import BaseAgent, event_bus
from app.config import settings


FILE_SIGNATURES = {
    ".pdf": (b"%PDF-", "PDF document"),
    ".png": (b"\x89PNG\r\n\x1a\n", "PNG image"),
    ".jpg": (b"\xff\xd8\xff", "JPEG image"),
    ".jpeg": (b"\xff\xd8\xff", "JPEG image"),
    ".gif": ((b"GIF87a", b"GIF89a"), "GIF image"),
    ".zip": (b"PK\x03\x04", "ZIP archive"),
    ".gz": (b"\x1f\x8b", "GZIP archive"),
    ".7z": (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    ".rar": ((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"), "RAR archive"),
    ".wasm": (b"\x00asm", "WebAssembly module"),
}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".com", ".scr"}


def _magic_type(content: bytes) -> tuple[str | None, bool]:
    if content.startswith(b"MZ"):
        # The DOS marker alone is common in arbitrary data. Require a bounded
        # e_lfanew pointer and the PE signature before identifying an executable.
        if len(content) >= 0x40:
            pe_offset = int.from_bytes(content[0x3C:0x40], "little")
            if 0x40 <= pe_offset <= len(content) - 4 and content[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                return "Windows PE executable", True
    if content.startswith(b"\x7fELF"):
        return "ELF executable", True
    if content.startswith(b"\x00asm"):
        return "WebAssembly module", True
    if content.startswith(b"PK\x03\x04"):
        return "ZIP container (package contents not validated)", False
    for _ext, (signature, description) in FILE_SIGNATURES.items():
        signatures = signature if isinstance(signature, tuple) else (signature,)
        if any(content.startswith(item) for item in signatures):
            return description, False
    return None, False


def _run_optional_scanners(content: bytes) -> list[dict]:
    """Run explicitly configured local scanners; never shell-expand input or claim isolation."""
    commands = []
    if settings.CLAMSCAN_PATH:
        commands.append(("ClamAV", [settings.CLAMSCAN_PATH, "--no-summary"]))
    if settings.YARA_PATH and settings.YARA_RULES_PATH:
        commands.append(("YARA", [settings.YARA_PATH, settings.YARA_RULES_PATH]))
    if not commands:
        return [{"name": "antivirus_yara", "status": "NOT_CONFIGURED"}]

    results = []
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="guard-ai-inspect-", suffix=".bin", delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(content)
        for name, command in commands:
            try:
                completed = subprocess.run(
                    [*command, temp_path], shell=False, capture_output=True, text=True, timeout=8,
                    check=False, env={"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
                )
                if name == "ClamAV":
                    status = "MALICIOUS" if completed.returncode == 1 else ("CLEAN" if completed.returncode == 0 else "ERROR")
                    finding = "Malware signature detected" if status == "MALICIOUS" else None
                else:
                    matched = completed.returncode == 0 and bool(completed.stdout.strip())
                    status = "RULE_MATCH" if matched else ("NO_MATCH" if completed.returncode == 1 else "ERROR")
                    finding = "Configured YARA rule matched; analyst review is required" if matched else None
                results.append({"name": name, "status": status, **({"finding": finding} if finding else {})})
            except (OSError, subprocess.TimeoutExpired):
                results.append({"name": name, "status": "ERROR"})
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                results.append({"name": "temporary_scan_file_cleanup", "status": "FAILED"})
    return results

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
            try:
                if os.path.getsize(filepath) > settings.MAX_UPLOAD_BYTES:
                    self.emit_event(
                        event_type="FILE_ANALYSIS_REJECTED",
                        payload={"reason": "File exceeds configured static-inspection size limit."},
                        severity="WARNING",
                    )
                    return
                with open(filepath, "rb") as f:
                    content = f.read(settings.MAX_UPLOAD_BYTES + 1)
                if len(content) > settings.MAX_UPLOAD_BYTES:
                    self.emit_event(
                        event_type="FILE_ANALYSIS_REJECTED",
                        payload={"reason": "File exceeded the size limit while being read."},
                        severity="WARNING",
                    )
                    return
            except OSError:
                self.emit_event(
                    event_type="FILE_ANALYSIS_REJECTED",
                    payload={"reason": "File could not be read for static inspection."},
                    severity="WARNING",
                )
                return
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

        if not isinstance(content, bytes):
            return {
                "filename": str(filename)[:255], "score": 100, "classification": "MALFORMED",
                "detected_file_type": "Invalid byte input", "file_type_verified": False,
                "indicators": ["File content must be supplied as bytes"], "matched_rules": [],
                "optional_scanners": [{"name": "antivirus_yara", "status": "NOT_RUN"}],
            }
        if len(content) > settings.MAX_UPLOAD_BYTES:
            return {
                "filename": str(filename)[:255], "size_bytes": len(content), "score": 100,
                "classification": "REJECTED", "detected_file_type": "Not analyzed",
                "file_type_verified": False,
                "indicators": ["File exceeds the configured static-inspection size limit"],
                "matched_rules": [],
                "optional_scanners": [{"name": "antivirus_yara", "status": "NOT_RUN"}],
            }

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
        ext = Path(filename).suffix.lower()
        detected_type, is_executable = _magic_type(content)
        package_extensions = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
        expected_extensions = {
            "Windows PE executable": EXECUTABLE_EXTENSIONS,
            "ELF executable": {".elf", ".so", ".bin", ""},
            "WebAssembly module": {".wasm"},
            "PDF document": {".pdf"}, "PNG image": {".png"}, "JPEG image": {".jpg", ".jpeg"},
            "GIF image": {".gif"},
            "ZIP container (package contents not validated)": {".zip"},
            "GZIP archive": {".gz", ".tgz"}, "7-Zip archive": {".7z"}, "RAR archive": {".rar"},
        }
        extension_match = ext in expected_extensions[detected_type] if detected_type in expected_extensions else None
        if detected_type == "ZIP container (package contents not validated)" and ext in package_extensions:
            extension_match = None
            indicators.append("ZIP container detected; office/document package contents were not validated")
        if extension_match is False:
            score += 55
            indicators.append(f"File signature ({detected_type}) conflicts with the .{ext.lstrip('.') or '[no extension]'} filename extension")
            if is_executable:
                score += 15
                indicators.append("Executable content is disguised with a non-executable filename extension")
        if is_executable:
            indicators.append(f"Executable signature identified: {detected_type}")

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

        optional_scanners = _run_optional_scanners(content)
        for scanner in optional_scanners:
            if scanner["status"] == "MALICIOUS":
                score += 100
                indicators.append(f"{scanner['name']} reported a configured malware signature match")
            elif scanner["status"] == "RULE_MATCH":
                score += 40
                indicators.append(f"{scanner['name']} rule matched; manual review is required")
            elif scanner["status"] == "FAILED":
                score += 20
                indicators.append("Temporary scanner input cleanup failed; operator review is required")

        final_score = min(score, 100)
        classification = "NO_KNOWN_INDICATORS"
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
            "is_executable": is_executable,
            "detected_file_type": detected_type or "Unknown / unsupported format",
            "file_type_verified": extension_match is True,
            "file_type_status": "VERIFIED_MATCH" if extension_match is True else ("SIGNATURE_MISMATCH" if extension_match is False else "UNVERIFIED"),
            "optional_scanners": optional_scanners,
            "score": final_score,
            "classification": classification,
            "matched_rules": matched_rules,
            "indicators": indicators if indicators else ["No known malicious patterns or abnormal entropy detected"],
            "verdict_scope": "Static heuristics and configured local scanners only; no file execution or dynamic sandboxing was performed.",
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
