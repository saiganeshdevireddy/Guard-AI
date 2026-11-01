"""
Specialized Wi-Fi & Network Security Agent.

Analyzes authorized local network parameters, flags insecure configurations,
open Wi-Fi risks, evil twin / rogue access point indicators, and DNS anomalies.
Strictly defensive: No unauthorized scanning, interference, or exploitation.
"""
from typing import Any, Dict, List, Optional
from app.agents.base import BaseAgent, event_bus

KNOWN_SECURE_DNS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}


class WifiSecurityAgent(BaseAgent):
    """Specialized agent for assessing Wi-Fi security postures and network telemetry."""

    def __init__(self):
        super().__init__(
            agent_id="agent_wifi_security",
            name="Wi-Fi Threat Detection Agent",
            role="Evaluates wireless security posture, encryption protocols, and rogue AP indicators"
        )

    def _register_event_handlers(self):
        event_bus.subscribe("AUDIT_NETWORK_REQUEST", self._on_audit_request)

    def _on_audit_request(self, event):
        network_data = event.payload
        result = self.analyze_network(network_data)
        self.emit_event(
            event_type="WIFI_AUDIT_COMPLETED",
            payload={"result": result},
            severity="HIGH" if result["risk_level"] in ["HIGH", "CRITICAL"] else "INFO"
        )

    def analyze_network(self, network_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates Wi-Fi network parameters:
        - ssid: Network name
        - security_type: OPEN, WEP, WPA_PSK, WPA2_PSK, WPA3_SAE, WPA2_ENTERPRISE
        - bssid: Hardware address
        - signal_strength_dbm: Optional RSSI
        - dns_servers: List of configured DNS IP addresses
        - captive_portal: Boolean indicating captive portal presence
        - duplicate_ssids_detected: Boolean or count of APs broadcasting identical SSID
        """
        self.task_count += 1
        self.heartbeat()

        ssid = network_info.get("ssid", "Unknown Network")
        sec_type = network_info.get("security_type", "OPEN").upper()
        bssid = network_info.get("bssid", "00:00:00:00:00:00")
        dns_servers = network_info.get("dns_servers", [])
        captive_portal = network_info.get("captive_portal", False)
        duplicate_ssids = network_info.get("duplicate_ssids_detected", 1)

        risk_score = 0
        vulnerabilities: List[str] = []
        recommendations: List[str] = []

        # 1. Security Protocol Analysis
        if sec_type in ["OPEN", "NONE", "UNENCRYPTED"]:
            risk_score += 60
            vulnerabilities.append("Network traffic is completely unencrypted. Anyone nearby can intercept packets.")
            recommendations.append("Avoid accessing sensitive accounts or banking on open Wi-Fi; activate a trusted VPN.")
        elif sec_type == "WEP":
            risk_score += 55
            vulnerabilities.append("Obsolete WEP encryption detected (vulnerable to passive IV cracking in minutes).")
            recommendations.append("Upgrade the router to WPA2-AES or WPA3 immediately.")
        elif sec_type == "WPA_PSK":
            risk_score += 35
            vulnerabilities.append("Legacy WPA-TKIP encryption in use (vulnerable to key reinstallation and Beck-Tews attacks).")
            recommendations.append("Configure the access point to use WPA2-PSK (AES) or WPA3.")
        elif sec_type in ["WPA2_PSK", "WPA2_AES"]:
            risk_score += 10
            recommendations.append("WPA2-AES is adequate. Enable WPA3 if your hardware supports it.")
        elif "WPA3" in sec_type:
            risk_score += 0
            recommendations.append("WPA3-SAE enabled: Robust protection against offline dictionary attacks.")

        # 2. Rogue AP / Evil Twin Indicator
        if duplicate_ssids > 1:
            risk_score += 40
            vulnerabilities.append(
                f"Multiple access points ({duplicate_ssids}) broadcasting the same SSID '{ssid}'. Potential Evil Twin / Wi-Fi Pineapple."
            )
            recommendations.append("Verify BSSID fingerprint with your network administrator before connecting.")

        # 3. Captive Portal Insecurity
        if captive_portal and sec_type == "OPEN":
            risk_score += 20
            vulnerabilities.append("Captive portal detected on unencrypted network. Prone to MITM credential harvesting.")
            recommendations.append("Do not enter real credentials or personal information on HTTP captive portal splash pages.")

        # 4. DNS configuration check
        suspicious_dns = [dns for dns in dns_servers if dns not in KNOWN_SECURE_DNS and not dns.startswith(("192.168.", "10.", "172.16."))]
        if suspicious_dns:
            risk_score += 25
            vulnerabilities.append(f"External non-standard DNS resolvers in use: {', '.join(suspicious_dns)} (Potential DNS hijacking)")
            recommendations.append("Configure DNS over HTTPS (DoH) or point DNS to 1.1.1.1 / 9.9.9.9.")

        final_score = min(risk_score, 100)
        risk_level = "LOW"
        if final_score >= 70:
            risk_level = "CRITICAL"
        elif final_score >= 45:
            risk_level = "HIGH"
        elif final_score >= 20:
            risk_level = "MEDIUM"

        result = {
            "ssid": ssid,
            "bssid": bssid,
            "security_type": sec_type,
            "risk_score": final_score,
            "risk_level": risk_level,
            "vulnerabilities": vulnerabilities if vulnerabilities else ["No immediate security vulnerabilities detected"],
            "recommendations": recommendations if recommendations else ["Current wireless configuration conforms to standard security baselines."],
        }
        self.metrics["last_audit"] = result
        return result

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        return self.analyze_network(message)
