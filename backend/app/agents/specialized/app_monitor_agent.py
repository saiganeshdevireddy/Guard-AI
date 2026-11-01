"""
Specialized Application Behaviour Monitoring Agent.

Monitors process telemetry, anomalous parent-child execution patterns,
path masquerading (e.g. svchost running outside System32), and resource spikes.
Maintains clear boundaries regarding OS permissions without claiming omniscient monitoring.
"""
from typing import Any, Dict, List, Optional
from app.agents.base import BaseAgent, event_bus

CRITICAL_SYSTEM_BINARIES = {
    "svchost.exe": "c:\\windows\\system32",
    "lsass.exe": "c:\\windows\\system32",
    "services.exe": "c:\\windows\\system32",
    "smss.exe": "c:\\windows\\system32",
    "csrss.exe": "c:\\windows\\system32",
    "explorer.exe": "c:\\windows",
}

SUSPICIOUS_PARENT_CHILD_PAIRS = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("acrobat.exe", "cmd.exe"),
    ("chrome.exe", "powershell.exe"),
    ("msedge.exe", "cmd.exe"),
]


class ApplicationBehaviourAgent(BaseAgent):
    """Specialized agent monitoring application behaviors and anomalous process trees."""

    def __init__(self):
        super().__init__(
            agent_id="agent_app_monitor",
            name="Application Behaviour Monitoring Agent",
            role="Inspects process hierarchies, masquerading binaries, and anomalous execution behavior"
        )

    def _register_event_handlers(self):
        event_bus.subscribe("ANALYZE_PROCESS_TELEMETRY", self._on_telemetry_request)

    def _on_telemetry_request(self, event):
        proc_data = event.payload
        result = self.analyze_process(proc_data)
        self.emit_event(
            event_type="PROCESS_BEHAVIOR_ANALYSIS_COMPLETED",
            payload={"result": result},
            severity="CRITICAL" if result["risk_level"] == "CRITICAL" else "INFO"
        )

    def analyze_process(self, process_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a process entry:
        - name: e.g. "powershell.exe"
        - pid: Process ID
        - parent_name: e.g. "winword.exe"
        - path: Executable path
        - command_line: Full arguments
        - cpu_percent: CPU utilization
        """
        self.task_count += 1
        self.heartbeat()

        proc_name = (process_info.get("name") or "").lower()
        parent_name = (process_info.get("parent_name") or "").lower()
        proc_path = (process_info.get("path") or "").lower()
        cmdline = (process_info.get("command_line") or "").lower()
        cpu_usage = process_info.get("cpu_percent", 0.0)

        risk_score = 0
        anomalies: List[str] = []

        # 1. Suspicious Parent-Child Process Spawning
        for parent, child in SUSPICIOUS_PARENT_CHILD_PAIRS:
            if parent in parent_name and child in proc_name:
                risk_score += 55
                anomalies.append(
                    f"Suspicious process lineage: Office/Browser '{parent}' spawned shell '{child}' (frequent initial access vector)"
                )
                break

        # 2. System Binary Masquerading Check
        if proc_name in CRITICAL_SYSTEM_BINARIES:
            expected_prefix = CRITICAL_SYSTEM_BINARIES[proc_name]
            if proc_path and not proc_path.startswith(expected_prefix):
                risk_score += 70
                anomalies.append(
                    f"System Binary Masquerading: '{proc_name}' running from '{proc_path}' instead of authorized directory '{expected_prefix}'"
                )

        # 3. High sustained CPU exhaustion (Cryptominer or Ransomware encryption loop)
        if cpu_usage > 85.0:
            risk_score += 30
            anomalies.append(f"Elevated sustained CPU utilization ({cpu_usage}%), potential cryptominer or rapid encryption loop")

        # 4. Command line indicators
        if any(arg in cmdline for arg in ["-encodedcommand", "-w hidden", "bypass", "unrestricted", "iex"]):
            risk_score += 40
            anomalies.append("Command-line invokes execution policy bypass or hidden window attributes")

        final_score = min(risk_score, 100)
        risk_level = "LOW"
        if final_score >= 70:
            risk_level = "CRITICAL"
        elif final_score >= 40:
            risk_level = "HIGH"
        elif final_score >= 20:
            risk_level = "MEDIUM"

        result = {
            "pid": process_info.get("pid", 0),
            "name": proc_name,
            "risk_score": final_score,
            "risk_level": risk_level,
            "anomalies": anomalies if anomalies else ["Process activity within normal operational parameters"],
            "recommended_action": "QUARANTINE_REQUEST" if final_score >= 70 else "MONITOR",
        }
        self.metrics["last_process_analysis"] = result
        return result

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        return self.analyze_process(message)
