"""
Specialized Phishing & Typosquatting Detection Agent.
"""
import math
import ipaddress
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

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

REDIRECT_PARAMETER_NAMES = {
    "url", "u", "next", "continue", "return", "return_url", "redirect", "redirect_url",
    "redirect_uri", "destination", "dest", "target", "callback", "to", "goto",
}


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
        if not isinstance(raw_url, str) or not raw_url.strip() or len(raw_url) > 2048:
            return {
                "url": str(raw_url)[:2048],
                "score": 100,
                "classification": "MALFORMED_URL",
                "indicators": ["URL is empty, not text, or exceeds the 2048 character limit"],
                "score_breakdown": [{"rule": "INVALID_INPUT", "points": 100}],
            }

        url = raw_url.strip()
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
            return {
                "url": raw_url[:2048], "score": 100, "classification": "MALFORMED_URL",
                "indicators": ["URL contains control characters"],
                "score_breakdown": [{"rule": "INVALID_URL", "points": 100}],
            }
        candidate = url if "://" in url else "https://" + url
        try:
            parsed = urlsplit(candidate)
            hostname = parsed.hostname or ""
            _ = parsed.port
            if (parsed.scheme.lower() not in {"http", "https"} or not hostname
                    or parsed.username is not None or parsed.password is not None):
                raise ValueError("unsupported or invalid URL")
            hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
            try:
                ipaddress.ip_address(hostname.strip("[]"))
                is_ip_literal = True
            except ValueError:
                is_ip_literal = False
            if not is_ip_literal and (
                len(hostname) > 253
                or any(
                    not label or len(label) > 63
                    or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                    for label in hostname.split(".")
                )
            ):
                raise ValueError("invalid hostname")
        except (ValueError, UnicodeError):
            return {
                "url": raw_url[:2048], "score": 100, "classification": "MALFORMED_URL",
                "indicators": ["Malformed, credential-bearing, or unsupported URL"],
                "score_breakdown": [{"rule": "INVALID_URL", "points": 100}],
            }

        path = parsed.path.lower()
        query = parsed.query.lower()

        score = 0
        indicators: List[str] = []
        score_breakdown: List[dict] = []

        def add(rule: str, points: int, explanation: str):
            nonlocal score
            score += points
            score_breakdown.append({"rule": rule, "points": points})
            indicators.append(explanation)

        # 1. IP Address check instead of legitimate domain name
        try:
            address = ipaddress.ip_address(hostname.strip("[]"))
            if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
                add("NON_PUBLIC_IP", 60, "Destination uses a non-public IP address")
            else:
                add("IP_LITERAL", 35, "Host is an IP literal rather than a registered domain")
        except ValueError:
            pass

        # 2. Suspicious TLD check
        domain_parts = hostname.split(".")
        tld = domain_parts[-1].lower() if len(domain_parts) > 1 else ""
        if tld in SUSPICIOUS_TLDS:
            add("SUSPICIOUS_TLD", 20, f"Domain uses a TLD associated with elevated abuse reports (.{tld})")

        # 3. Excessive subdomains
        if len(domain_parts) >= 4:
            add("NESTED_SUBDOMAINS", 15, f"Host contains unusually deep subdomain nesting ({len(domain_parts)} labels)")

        # 4. Keyword presence in subdomain/path
        matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in (hostname + path + query)]
        if matched_keywords:
            add("CREDENTIAL_KEYWORDS", min(30, 10 * len(matched_keywords[:3])),
                f"URL contains credential-related terms: {', '.join(matched_keywords[:3])}")

        # 5. Excessive hyphenation
        if hostname.count("-") >= 2:
            add("HYPHENATED_HOST", 10, "Host contains multiple hyphens")

        # 6. Typosquatting / Brand Spoofing evaluation
        base_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
        for brand in HIGH_VALUE_TARGETS:
            brand_name = brand.split(".")[0]
            if (re.search(rf"(^|[.-]){re.escape(brand_name)}([.-]|$)", hostname)
                    and base_domain != brand and (hostname == brand or hostname.endswith("." + brand)) is False):
                add("BRAND_IMPERSONATION", 35, f"Brand-like hostname pattern is present outside {brand}")
                break
            
            # Check Levenshtein distance for typosquatting (e.g. paypa1.com, micros0ft.com)
            dist = levenshtein_distance(base_domain, brand)
            if dist == 1:
                add("POSSIBLE_TYPOSQUAT", 50, f"Host closely resembles the known brand domain {brand}")
                break
            elif dist == 2 and len(brand) > 8:
                add("POSSIBLE_TYPOSQUAT", 25, f"Host has some similarity to the known brand domain {brand}")
                break

        # 7. Entropy of domain name
        entropy = calculate_entropy(domain_parts[0])
        if entropy > 3.8 and len(domain_parts[0]) > 10:
            add("HIGH_HOST_ENTROPY", 15, f"Host label has elevated character entropy ({entropy:.2f})")

        redirect_findings = []
        try:
            query_fields = parse_qsl(parsed.query, keep_blank_values=False, max_num_fields=100)
        except ValueError:
            query_fields = []
            add("EXCESSIVE_QUERY_FIELDS", 15, "URL contains more than 100 query fields; redirect analysis was bounded")
        for key, value in query_fields:
            if key.lower() not in REDIRECT_PARAMETER_NAMES:
                continue
            candidate_target = unquote(value.strip())
            if not candidate_target or len(candidate_target) > 2048:
                continue
            if candidate_target.startswith(("//", "\\\\")):
                candidate_target = parsed.scheme + ":" + candidate_target
            elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate_target):
                continue
            try:
                target_parts = urlsplit(candidate_target)
                _ = target_parts.port
                target_host = (target_parts.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
                if target_parts.scheme.lower() not in {"http", "https"} or not target_host:
                    continue
            except (ValueError, UnicodeError):
                add("MALFORMED_REDIRECT_TARGET", 20, "A redirect-like parameter contains a malformed destination")
                break
            if target_host != hostname:
                redirect_findings.append(target_host)
        if redirect_findings:
            unique_targets = sorted(set(redirect_findings))[:3]
            add("EXTERNAL_REDIRECT_PARAMETER", 20,
                "URL contains a redirect-style parameter pointing to a different host; this is a pattern, not proof of an actual redirect")

        final_score = min(score, 100)
        classification = "NO_KNOWN_INDICATORS"
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
            "verdict_scope": "Heuristic only. A low score does not establish that the URL is safe.",
            "indicators": indicators if indicators else ["No suspicious phishing markers identified"],
            "entropy": round(entropy, 2),
            "score_breakdown": score_breakdown,
            "redirect_targets_observed": sorted(set(redirect_findings))[:3],
            "fetch_performed": False,
        }
        self.metrics["last_scan"] = result
        return result

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        url = message.get("url")
        if not url:
            return {"error": "Missing 'url' parameter"}
        return self.analyze_url(url)
