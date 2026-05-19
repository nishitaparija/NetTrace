"""
http_anomaly.py
T1071.001 / T1552.001 / T1048.001 — HTTP Anomaly Detection
Author: Nishita Parija

Detection logic:
  1. Suspicious User-Agent strings (scanning / exploitation tools).
  2. Clear-text credential patterns in HTTP POST body or URI.
  3. Anomalously large HTTP POST requests (potential exfiltration).
"""

from __future__ import annotations
import re
from collections import defaultdict

try:
    from scapy.all import IP, TCP, Raw
except ImportError:
    pass

from modules.mitre_mapper import get_technique

LARGE_POST_THRESHOLD = 512 * 1024   # 512 KB in bytes

SUSPICIOUS_UA_PATTERNS = [
    (r"sqlmap",               "SQLmap SQL injection scanner"),
    (r"nikto",                "Nikto web vulnerability scanner"),
    (r"\bnmap\b",             "Nmap port / service scanner"),
    (r"masscan",              "Masscan port scanner"),
    (r"zgrab",                "ZGrab banner grabber"),
    (r"dirbuster",            "DirBuster directory brute-forcer"),
    (r"gobuster",             "GoBuster directory/DNS brute-forcer"),
    (r"python-requests/2\.",  "Python Requests library (scripted)"),
    (r"Go-http-client/1\.1",  "Go HTTP client (scripted)"),
    (r"curl/7\.",             "cURL command-line tool"),
    (r"Hydra",                "Hydra brute-force tool"),
    (r"libwww-perl",          "libwww-perl (scripted)"),
    (r"OWASP",                "OWASP testing tool"),
    (r"w3af",                 "W3AF web application scanner"),
]

CRED_PATTERNS = [
    rb"password=([^&\s]{3,})",
    rb"passwd=([^&\s]{3,})",
    rb"pass=([^&\s]{3,})",
    rb"pwd=([^&\s]{3,})",
    rb"Authorization: Basic ([A-Za-z0-9+/=]{4,})",
]

UA_PATTERN = re.compile(rb"User-Agent: ([^\r\n]+)", re.IGNORECASE)
POST_PATTERN = re.compile(rb"POST ([^\s]+) HTTP", re.IGNORECASE)
CONTENT_LEN  = re.compile(rb"Content-Length: (\d+)", re.IGNORECASE)


class HttpAnomalyDetector:

    def __init__(self, packets: list, thresholds: dict, verbose: bool = False):
        self.packets   = packets
        self.verbose   = verbose

    def analyse(self) -> list[dict]:
        findings: list[dict] = []
        findings += self._detect_suspicious_ua()
        findings += self._detect_cleartext_creds()
        findings += self._detect_large_post()
        return findings

    # ─────────────────────────────────────────────────────────────────────────

    def _detect_suspicious_ua(self) -> list[dict]:
        att = get_technique("http_suspicious_ua")
        results: list[dict] = []
        seen_uas: set = set()

        for pkt in self.packets:
            if IP not in pkt or TCP not in pkt or Raw not in pkt:
                continue
            payload = bytes(pkt[Raw])
            if b"HTTP/" not in payload and b"GET " not in payload and b"POST " not in payload:
                continue

            ua_match = UA_PATTERN.search(payload)
            if not ua_match:
                continue

            try:
                ua = ua_match.group(1).decode("utf-8", errors="ignore").strip()
            except Exception:
                continue

            if ua in seen_uas:
                continue

            for pattern, tool_name in SUSPICIOUS_UA_PATTERNS:
                if re.search(pattern, ua, re.IGNORECASE):
                    seen_uas.add(ua)
                    src = pkt[IP].src if IP in pkt else "unknown"
                    dst = pkt[IP].dst if IP in pkt else "unknown"
                    results.append({
                        "title":      f"Scanning Tool UA — {tool_name} from {src}",
                        "severity":   "HIGH",
                        "detector":   "HttpAnomalyDetector",
                        "source_ip":  src,
                        "dest_ip":    dst,
                        "user_agent": ua,
                        "tool":       tool_name,
                        "detail": (
                            f"HTTP request from {src} to {dst} carries User-Agent string "
                            f"associated with {tool_name}: '{ua}'. "
                            "Indicates active reconnaissance, scanning, or exploitation."
                        ),
                        "mitre": att,
                        "recommendation": (
                            f"Block source IP {src} at the WAF and perimeter firewall. "
                            "Review web server access logs for full scope of activity. "
                            "Inspect for exploitation attempts beyond reconnaissance."
                        ),
                    })
                    break

        return results

    # ─────────────────────────────────────────────────────────────────────────

    def _detect_cleartext_creds(self) -> list[dict]:
        att = get_technique("http_cleartext_creds")
        results: list[dict] = []
        seen_srcs: set = set()

        for pkt in self.packets:
            if IP not in pkt or TCP not in pkt or Raw not in pkt:
                continue
            payload = bytes(pkt[Raw])

            for pattern in CRED_PATTERNS:
                m = re.search(pattern, payload, re.IGNORECASE)
                if m:
                    src = pkt[IP].src if IP in pkt else "unknown"
                    dst = pkt[IP].dst if IP in pkt else "unknown"
                    key = (src, dst)
                    if key in seen_srcs:
                        continue
                    seen_srcs.add(key)

                    results.append({
                        "title":     f"Clear-Text Credentials in HTTP — {src} → {dst}",
                        "severity":  "HIGH",
                        "detector":  "HttpAnomalyDetector",
                        "source_ip": src,
                        "dest_ip":   dst,
                        "detail": (
                            f"HTTP traffic between {src} and {dst} contains credential "
                            "patterns (password/passwd/Authorization: Basic) in plain text. "
                            "This exposes credentials to interception attacks."
                        ),
                        "mitre": att,
                        "recommendation": (
                            "Enforce HTTPS across all authentication endpoints (HSTS). "
                            "Immediately rotate potentially exposed credentials. "
                            "Review authentication implementation for secure practices."
                        ),
                    })
                    break

        return results

    # ─────────────────────────────────────────────────────────────────────────

    def _detect_large_post(self) -> list[dict]:
        att = get_technique("http_large_post")
        results: list[dict] = []

        for pkt in self.packets:
            if IP not in pkt or TCP not in pkt or Raw not in pkt:
                continue
            payload = bytes(pkt[Raw])

            if not POST_PATTERN.search(payload):
                continue

            cl_match = CONTENT_LEN.search(payload)
            if cl_match:
                try:
                    content_len = int(cl_match.group(1))
                except ValueError:
                    continue

                if content_len >= LARGE_POST_THRESHOLD:
                    src = pkt[IP].src if IP in pkt else "unknown"
                    dst = pkt[IP].dst if IP in pkt else "unknown"
                    uri_match = POST_PATTERN.search(payload)
                    uri = uri_match.group(1).decode("utf-8", errors="ignore") if uri_match else "/"
                    results.append({
                        "title":       f"Large HTTP POST — {src} → {dst} ({content_len//1024} KB)",
                        "severity":    "MEDIUM",
                        "detector":    "HttpAnomalyDetector",
                        "source_ip":   src,
                        "dest_ip":     dst,
                        "uri":         uri,
                        "content_length_bytes": content_len,
                        "detail": (
                            f"HTTP POST from {src} to {dst}{uri} carries "
                            f"{content_len // 1024} KB of body data "
                            f"(threshold: {LARGE_POST_THRESHOLD // 1024} KB). "
                            "Large POST bodies may indicate staged data exfiltration "
                            "via HTTP to an external server."
                        ),
                        "mitre": att,
                        "recommendation": (
                            "Inspect POST body content for sensitive data or archives. "
                            "Verify legitimacy of large uploads with the data owner. "
                            "Implement DLP controls on HTTP egress. "
                            "Review destination IP against threat intelligence."
                        ),
                    })

        return results[:10]
