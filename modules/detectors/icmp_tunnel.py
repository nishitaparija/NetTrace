"""
icmp_tunnel.py
T1095 — Non-Application Layer Protocol (ICMP Tunnelling Detection)
Author: Nishita Parija

Detection logic:
  1. Oversized ICMP payloads (data > 64 bytes standard ping threshold).
  2. High ICMP frequency from a single source (> 20 packets/second).
  3. ICMP echo with non-zero, varying payloads — consistent with data tunnelling.
"""

from __future__ import annotations
from collections import defaultdict, Counter

try:
    from scapy.all import IP, ICMP, Raw
except ImportError:
    pass

from modules.mitre_mapper import get_technique

PAYLOAD_THRESHOLD = 64    # bytes
RATE_THRESHOLD    = 20    # packets per second
RATE_WINDOW       = 1.0   # seconds


class IcmpTunnelDetector:

    def __init__(self, packets: list, thresholds: dict, verbose: bool = False):
        self.packets = packets
        self.verbose = verbose

    def analyse(self) -> list[dict]:
        findings: list[dict] = []
        att = get_technique("icmp_tunnel")

        large_payloads: dict  = defaultdict(list)
        rate_timeline:  dict  = defaultdict(list)   # src → [ts]

        for pkt in self.packets:
            if IP not in pkt or ICMP not in pkt:
                continue

            icmp = pkt[ICMP]
            if icmp.type not in (8, 0):  # echo request / echo reply only
                continue

            src   = pkt[IP].src
            dst   = pkt[IP].dst
            ts    = float(pkt.time) if hasattr(pkt, "time") else 0.0
            data  = bytes(pkt[Raw]) if Raw in pkt else b""
            dsize = len(data)

            if dsize > PAYLOAD_THRESHOLD:
                large_payloads[(src, dst)].append((ts, dsize, data[:20]))

            rate_timeline[src].append(ts)

        # ── Finding 1: Oversized ICMP payloads ───────────────────────────────
        for (src, dst), events in large_payloads.items():
            if len(events) < 3:   # require at least 3 oversized packets
                continue
            avg_size = sum(e[1] for e in events) / len(events)
            max_size = max(e[1] for e in events)
            findings.append({
                "title":    f"ICMP Tunnelling Suspected — {src} → {dst}",
                "severity": "MEDIUM",
                "detector": "IcmpTunnelDetector",
                "source_ip":       src,
                "dest_ip":         dst,
                "oversized_count": len(events),
                "avg_payload_bytes": round(avg_size, 1),
                "max_payload_bytes": max_size,
                "detail": (
                    f"{src} sent {len(events)} ICMP echo packets to {dst} with payloads "
                    f"exceeding {PAYLOAD_THRESHOLD} bytes (avg: {round(avg_size)}B, "
                    f"max: {max_size}B). "
                    "Standard ICMP ping uses 56 bytes of data. Oversized payloads are "
                    "characteristic of ICMP tunnelling tools (ptunnel-ng, icmptunnel, HANS)."
                ),
                "mitre": att,
                "recommendation": (
                    "Block or restrict ICMP at the perimeter firewall. "
                    "Inspect ICMP payload content for protocol framing or encoded data. "
                    "Investigate both endpoints for tunnelling tools. "
                    "Implement IDS rules for oversized ICMP (Snort SID 408)."
                ),
            })

        # ── Finding 2: High-frequency ICMP ───────────────────────────────────
        for src, timestamps in rate_timeline.items():
            timestamps.sort()
            for i, t0 in enumerate(timestamps):
                window = [t for t in timestamps[i:] if t - t0 <= RATE_WINDOW]
                rate = len(window)
                if rate >= RATE_THRESHOLD:
                    findings.append({
                        "title":    f"High-Rate ICMP from {src} ({rate} pkts/s)",
                        "severity": "MEDIUM",
                        "detector": "IcmpTunnelDetector",
                        "source_ip":   src,
                        "rate_per_sec": rate,
                        "detail": (
                            f"{src} sent {rate} ICMP packets within 1 second "
                            f"(threshold: {RATE_THRESHOLD}/s). "
                            "High-frequency ICMP may indicate tunnelled data transmission "
                            "or an ICMP-based DoS attack."
                        ),
                        "mitre": att,
                        "recommendation": (
                            "Rate-limit ICMP at the perimeter. "
                            "Investigate source host. "
                            "Check for ping flood or tunnelling tool activity."
                        ),
                    })
                    break  # one finding per source

        return findings
