"""
dns_analysis.py
T1048.003 / T1071.004 — DNS Exfiltration and Tunnelling Detection
Author: Nishita Parija

Detection logic:
  1. Long query labels (subdomain > 52 chars) — data encoded in DNS
  2. High Shannon entropy (> 3.5) on subdomain — base64/hex encoding
  3. High query frequency (> 30 queries/min to same domain) — DNS tunnelling
  4. TXT record queries from RFC1918 hosts — common exfil channel
  5. Non-standard DNS port usage (not 53) — evasion attempt
"""

from __future__ import annotations
import math
import re
import ipaddress
from collections import Counter, defaultdict
from statistics import mean

try:
    from scapy.all import IP, UDP, TCP, DNS, DNSQR
except ImportError:
    pass

from modules.mitre_mapper import get_technique

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in _PRIVATE_NETS)
    except ValueError:
        return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _base_domain(fqdn: str) -> str:
    """Extract base domain (last two labels) from FQDN."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


class DnsAnalysisDetector:

    def __init__(self, packets: list, thresholds: dict, verbose: bool = False):
        self.packets    = packets
        self.verbose    = verbose
        self.len_thresh = 52
        self.ent_thresh = 3.5
        self.rate_thresh = 30  # queries/minute

    def analyse(self) -> list[dict]:
        findings: list[dict] = []

        queries: list[dict] = []
        domain_ts: dict = defaultdict(list)   # base_domain → [timestamp]

        for pkt in self.packets:
            if DNS not in pkt or pkt[DNS].qr != 0:   # only queries
                continue
            if DNSQR not in pkt:
                continue

            ts  = float(pkt.time) if hasattr(pkt, "time") else 0.0
            src = pkt[IP].src if IP in pkt else "unknown"

            try:
                qname  = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype  = pkt[DNSQR].qtype
            except Exception:
                continue

            subdomain = qname.split(".")[0] if "." in qname else qname
            entropy   = _shannon_entropy(subdomain)
            base      = _base_domain(qname)
            port      = pkt[UDP].dport if UDP in pkt else (pkt[TCP].dport if TCP in pkt else 53)

            queries.append({
                "ts": ts, "src": src, "qname": qname, "qtype": qtype,
                "subdomain": subdomain, "entropy": entropy, "base": base, "port": port,
            })
            domain_ts[base].append(ts)

        # ── Detection 1: Long / high-entropy queries ──────────────────────────
        att_exfil = get_technique("dns_exfil")
        seen: set = set()
        for q in queries:
            qname   = q["qname"]
            entropy = q["entropy"]
            if qname in seen:
                continue

            if len(qname) > self.len_thresh or entropy > self.ent_thresh:
                seen.add(qname)
                reason = []
                if len(qname) > self.len_thresh:
                    reason.append(f"query length {len(qname)} chars (threshold: {self.len_thresh})")
                if entropy > self.ent_thresh:
                    reason.append(f"subdomain entropy {round(entropy, 3)} (threshold: {self.ent_thresh})")
                findings.append({
                    "title":    f"Potential DNS Exfiltration — {qname[:60]}{'...' if len(qname)>60 else ''}",
                    "severity": "HIGH",
                    "detector": "DnsAnalysisDetector",
                    "source_ip":  q["src"],
                    "query":      qname,
                    "entropy":    round(entropy, 3),
                    "query_len":  len(qname),
                    "detail": (
                        f"Anomalous DNS query from {q['src']}: {', '.join(reason)}. "
                        "Long or high-entropy subdomains are characteristic of data "
                        "encoded (base64/hex) within DNS query strings for exfiltration."
                    ),
                    "mitre": att_exfil,
                    "recommendation": (
                        "Inspect full DNS query payload for encoded data. "
                        "Block queries to this domain at the DNS resolver. "
                        "Investigate source host for data theft malware (DNS Messenger, "
                        "DNScat2, Iodine)."
                    ),
                })

        # ── Detection 2: High query frequency (DNS tunnelling) ────────────────
        att_tunnel = get_technique("dns_tunnel")
        for base, timestamps in domain_ts.items():
            if len(timestamps) < 10:
                continue
            timestamps.sort()
            # Sliding 60-second window
            for i, ts_start in enumerate(timestamps):
                window = [t for t in timestamps[i:] if t - ts_start <= 60]
                rate = len(window)
                if rate >= self.rate_thresh:
                    findings.append({
                        "title":    f"DNS Tunnelling Suspected — {base} ({rate} queries/min)",
                        "severity": "HIGH",
                        "detector": "DnsAnalysisDetector",
                        "domain":   base,
                        "queries_per_minute": rate,
                        "detail": (
                            f"{rate} DNS queries to {base} within a 60-second window "
                            f"(threshold: {self.rate_thresh}/min). "
                            "High-frequency DNS queries to a single domain are a "
                            "characteristic of DNS tunnelling tools (DNScat2, Iodine, dnstt)."
                        ),
                        "mitre": att_tunnel,
                        "recommendation": (
                            f"Block DNS queries to {base} at the resolver. "
                            "Investigate source hosts initiating queries. "
                            "Capture and inspect DNS payloads for tunnel protocol framing. "
                            "Implement DNS rate-limiting policy."
                        ),
                    })
                    break  # one finding per domain

        # ── Detection 3: TXT record queries from internal hosts ───────────────
        for q in queries:
            if q["qtype"] == 16 and _is_private(q["src"]):  # QTYPE 16 = TXT
                findings.append({
                    "title":    f"Suspicious DNS TXT Query from Internal Host {q['src']}",
                    "severity": "MEDIUM",
                    "detector": "DnsAnalysisDetector",
                    "source_ip": q["src"],
                    "query":     q["qname"],
                    "detail": (
                        f"Internal host {q['src']} issued a DNS TXT record query for "
                        f"'{q['qname']}'. TXT records are commonly abused for command "
                        "delivery or data exfiltration in stage-2 malware implants."
                    ),
                    "mitre": att_exfil,
                    "recommendation": (
                        "Inspect the TXT record response content. "
                        "Block TXT queries from internal hosts to external resolvers. "
                        "Investigate source host for malware using DNS for C2 staging."
                    ),
                })

        # ── Detection 4: Non-standard DNS port ───────────────────────────────
        for q in queries:
            if q["port"] != 53:
                findings.append({
                    "title":    f"DNS on Non-Standard Port {q['port']} from {q['src']}",
                    "severity": "MEDIUM",
                    "detector": "DnsAnalysisDetector",
                    "source_ip": q["src"],
                    "port":      q["port"],
                    "detail": (
                        f"DNS query from {q['src']} sent to port {q['port']} instead of "
                        "standard port 53. This may indicate DNS-over-non-standard-port "
                        "evasion or an unusual DNS resolver."
                    ),
                    "mitre": att_tunnel,
                    "recommendation": (
                        "Block outbound DNS traffic on all ports except 53 and 853 (DoT). "
                        "Enforce DNS traffic redirection to authorised internal resolvers."
                    ),
                })
                break  # one finding for non-std port

        return findings[:30]
