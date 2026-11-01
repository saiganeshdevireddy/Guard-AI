"""
Specialized Phishing & Typosquatting Detection Agent.
"""
import math
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from app.agents.base import BaseAgent, event_bus


# Well-known brands frequently targeted by phishing campaigns
HIGH_VALUE_TARGETS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "netflix.com",
    "github.com", "facebook.com", "instagram.com", "twitter.com", "dropbox.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "work", "click", "rest", "party", "country"
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "password", "credential", "confirm", "wallet", "invoice", "suspended"
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect algorithmically generated or randomized domains."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class PhishingDetectionAgent(BaseAgent):
    """Specialized agent dedicated to lexical, brand spoofing, and typosquatting analysis."""

    def __init__(self):
        super().__init__(
            agent_id="agent_phishing",
            name="Phishing Detection Agent",
            role="Detects phishing indicators, brand spoofing, and typosquatting in URLs"
        )

    def _register_event_handlers(self):
        event_bus.subscribe("SCAN_URL_REQUEST", self._on_scan_request)

    def _on_scan_request(self, event):
        url = event.payload.get("url")
        if url:
            result = self.analyze_url(url)
            self.emit_event(
                event_type="PHISHING_ANALYSIS_COMPLETED",
                payload={"url": url, "result": result},
                severity="HIGH" if result["score"] >= 65 else "INFO"
            )

    def analyze_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Comprehensive lexical and semantic phishing evaluation of a URL.
        """
        self.task_count += 1
        self.heartbeat()

        # Normalization
        url = raw_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            path = parsed.path.lower()
            query = parsed.query.lower()
        except Exception:
            return {
                "score": 85,
                "classification": "MALFORMED_URL",
                "indicators": ["Malformed or unparseable URL structure"],
                "confidence": 0.9,
            }

        score = 0
        indicators: List[str] = []

        # 1. IP Address check instead of legitimate domain name
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            score += 40
            indicators.append(f"Host uses bare IP address ({hostname}) rather than a registered domain")

        # 2. Suspicious TLD check
        domain_parts = hostname.split(".")
        tld = domain_parts[-1].lower() if len(domain_parts) > 1 else ""
        if tld in SUSPICIOUS_TLDS:
            score += 25
            indicators.append(f"Domain uses high-abuse top-level domain (.{tld})")

        # 3. Excessive subdomains
        if len(domain_parts) >= 4:
            score += 20
            indicators.append(f"Excessive subdomain nesting ({len(domain_parts)} levels) used to obscure real host")

        # 4. Keyword presence in subdomain/path
        matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in (hostname + path + query)]
        if matched_keywords:
            score += 15 * len(matched_keywords[:3])
            indicators.append(f"Detected credential harvesting keywords: {', '.join(matched_keywords)}")

        # 5. Excessive hyphenation
        if hostname.count("-") >= 2:
            score += 15
            indicators.append(f"Unusual hyphenation in domain ({hostname.count('-')} hyphens)")

        # 6. Typosquatting / Brand Spoofing evaluation
        base_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
        for brand in HIGH_VALUE_TARGETS:
            brand_name = brand.split(".")[0]
            if brand_name in hostname and base_domain != brand:
                score += 45
                indicators.append(f"Brand spoofing detected: '{brand_name}' embedded in untrusted host '{hostname}'")
                break
            
            # Check Levenshtein distance for typosquatting (e.g. paypa1.com, micros0ft.com)
            dist = levenshtein_distance(base_domain, brand)
            if dist == 1:
                score += 55
                indicators.append(f"High-confidence typosquatting of '{brand}' (edit distance 1 from '{base_domain}')")
                break
            elif dist == 2 and len(brand) > 8:
                score += 35
                indicators.append(f"Possible typosquatting of '{brand}' (edit distance 2)")
                break

        # 7. Entropy of domain name
        entropy = calculate_entropy(domain_parts[0])
        if entropy > 3.8 and len(domain_parts[0]) > 10:
            score += 20
            indicators.append(f"High domain entropy ({entropy:.2f}), possible DGA (domain generation algorithm)")

        final_score = min(score, 100)
        classification = "SAFE"
        if final_score >= 70:
            classification = "CRITICAL_PHISHING"
        elif final_score >= 40:
            classification = "SUSPICIOUS"
        elif final_score >= 20:
            classification = "LOW_RISK"

        result = {
            "url": raw_url,
            "hostname": hostname,
            "score": final_score,
            "classification": classification,
            "indicators": indicators if indicators else ["No suspicious phishing markers identified"],
            "entropy": round(entropy, 2),
        }
        self.metrics["last_scan"] = result
        return result

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        url = message.get("url")
        if not url:
            return {"error": "Missing 'url' parameter"}
        return self.analyze_url(url)
