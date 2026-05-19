"""
ioc_extractor.py
Extracts Indicators of Compromise (IOCs) from parsed packets.
Author: Nishita Parija
"""

from __future__ import annotations
import ipaddress
import re
from collections import Counter, defaultdict
from typing import Optional

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, HTTPRequest
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Known suspicious / scanning User-Agent substrings
# ─────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_UA_PATTERNS = [
    r"sqlmap", r"nikto", r"\bnmap\b", r"masscan", r"zgrab",
    r"python-requests/2\.\d+\.\d+", r"Go-http-client/1\.1",
    r"curl/7\.", r"libwww-perl", r"Hydra", r"dirbuster",
]

# RFC 1918 private address ranges
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    import math
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


class IocExtractor:
    """
    Scans packets for:
    - Suspicious external IP addresses (non-RFC1918 destinations)
    - Anomalous DNS domain queries (high entropy / long labels)
    - Suspicious HTTP User-Agent strings
    """

    def __init__(self, packets: list):
        self.packets = packets

    def extract(self) -> dict:
        """Run all IOC extraction and return structured results."""
        return {
            "ips":         self._extract_suspicious_ips(),
            "domains":     self._extract_suspicious_domains(),
            "user_agents": self._extract_suspicious_user_agents(),
        }

    # ─────────────────────────────────────────────────────────────────────────
    # IP extraction
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_suspicious_ips(self) -> list[dict]:
        """
        Flag external IPs that receive unusually high connection volumes
        from internal hosts (potential C2 or scanning targets).
        Threshold: > 50 unique packets to/from a single external IP.
        """
        ext_dst: Counter = Counter()
        for pkt in self.packets:
            if IP in pkt:
                dst = pkt[IP].dst
                if not _is_private(dst):
                    ext_dst[dst] += 1

        suspicious = []
        for ip, count in ext_dst.most_common(20):
            if count >= 50:
                suspicious.append({"ip": ip, "packet_count": count})
        return suspicious

    # ─────────────────────────────────────────────────────────────────────────
    # DNS domain extraction
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_suspicious_domains(self) -> list[dict]:
        """
        Flag DNS queries where:
        - Total query length > 52 characters, OR
        - Shannon entropy of subdomain > 3.5 (likely encoded)
        """
        suspicious = []
        seen: set = set()

        for pkt in self.packets:
            if DNS in pkt and pkt[DNS].qr == 0:  # DNS query
                try:
                    qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    continue

                if qname in seen:
                    continue
                seen.add(qname)

                subdomain = qname.split(".")[0] if "." in qname else qname
                entropy   = _shannon_entropy(subdomain)
                length    = len(qname)

                if length > 52 or entropy > 3.5:
                    suspicious.append({
                        "domain":    qname,
                        "length":    length,
                        "entropy":   round(entropy, 3),
                        "reason":    "high entropy" if entropy > 3.5 else "long query",
                    })

        return suspicious[:50]  # cap to 50

    # ─────────────────────────────────────────────────────────────────────────
    # User-Agent extraction
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_suspicious_user_agents(self) -> list[dict]:
        """
        Scan HTTP request headers for User-Agent strings matching
        known scanning / exploitation tool patterns.
        """
        suspicious = []
        seen_uas: set = set()
        ua_pattern = re.compile(b"User-Agent: ([^\r\n]+)", re.IGNORECASE)

        for pkt in self.packets:
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw])
                match = ua_pattern.search(payload)
                if not match:
                    continue
                ua_bytes = match.group(1)
                try:
                    ua = ua_bytes.decode("utf-8", errors="ignore").strip()
                except Exception:
                    continue

                if ua in seen_uas:
                    continue
                seen_uas.add(ua)

                for pattern in SUSPICIOUS_UA_PATTERNS:
                    if re.search(pattern, ua, re.IGNORECASE):
                        src_ip = pkt[IP].src if IP in pkt else "unknown"
                        dst_ip = pkt[IP].dst if IP in pkt else "unknown"
                        suspicious.append({
                            "user_agent": ua,
                            "src_ip":     src_ip,
                            "dst_ip":     dst_ip,
                            "matched_pattern": pattern,
                        })
                        break

        return suspicious
