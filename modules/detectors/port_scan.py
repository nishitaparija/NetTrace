"""
port_scan.py
T1046 — Network Service Discovery (Port Scanning Detection)
Author: Nishita Parija

Detection logic:
  Sliding 5-second window per source IP. If a source connects to ≥ threshold
  unique destination ports within any 5-second window, a port scan is flagged.
  SYN-only packets (no ACK) are weighted separately as half-open/stealth scans.
"""

from __future__ import annotations
from collections import defaultdict
from typing import Optional

try:
    from scapy.all import IP, TCP, UDP
except ImportError:
    pass

from modules.mitre_mapper import get_technique

WINDOW_SECONDS = 5


class PortScanDetector:

    def __init__(self, packets: list, thresholds: dict, verbose: bool = False):
        self.packets   = packets
        self.threshold = thresholds.get("scan_threshold", 15)
        self.verbose   = verbose

    def analyse(self) -> list[dict]:
        findings: list[dict] = []

        # Build per-source timeline: {src_ip: [(timestamp, dst_port, is_syn_only), ...]}
        timeline: dict = defaultdict(list)

        for pkt in self.packets:
            if IP not in pkt:
                continue

            src = pkt[IP].src
            ts  = float(pkt.time) if hasattr(pkt, "time") else 0.0

            if TCP in pkt:
                flags     = pkt[TCP].flags
                is_syn    = bool(flags & 0x02)   # SYN set
                is_ack    = bool(flags & 0x10)   # ACK set
                syn_only  = is_syn and not is_ack
                dst_port  = pkt[TCP].dport
                timeline[src].append((ts, dst_port, syn_only, "TCP"))

            elif UDP in pkt:
                dst_port = pkt[UDP].dport
                timeline[src].append((ts, dst_port, False, "UDP"))

        # Sliding window analysis
        for src, events in timeline.items():
            events.sort(key=lambda x: x[0])
            n = len(events)
            i = 0
            while i < n:
                window_start = events[i][0]
                window_end   = window_start + WINDOW_SECONDS
                j = i
                ports_in_window: set = set()
                syn_only_count = 0

                while j < n and events[j][0] <= window_end:
                    ports_in_window.add(events[j][1])
                    if events[j][2]:  # syn_only
                        syn_only_count += 1
                    j += 1

                unique_ports = len(ports_in_window)
                if unique_ports >= self.threshold:
                    scan_type = "SYN Scan (stealth)" if syn_only_count > unique_ports * 0.7 else "Connect Scan"
                    technique_key = "port_scan_syn" if "SYN" in scan_type else "port_scan_connect"
                    att = get_technique(technique_key)
                    findings.append({
                        "title":          f"Port Scan Detected — {scan_type}",
                        "severity":       "HIGH",
                        "detector":       "PortScanDetector",
                        "source_ip":      src,
                        "unique_ports":   unique_ports,
                        "window_seconds": WINDOW_SECONDS,
                        "scan_type":      scan_type,
                        "detail":         (
                            f"Source {src} probed {unique_ports} unique destination ports "
                            f"within {WINDOW_SECONDS}s ({syn_only_count} SYN-only packets). "
                            f"Threshold: {self.threshold} ports/{WINDOW_SECONDS}s."
                        ),
                        "mitre": att,
                        "recommendation": (
                            "Investigate source host for compromise or authorised scanning activity. "
                            "Block or rate-limit outbound port sweeps at the perimeter. "
                            "Correlate source IP against threat intelligence feeds."
                        ),
                    })
                    # Skip to the end of this window to avoid duplicate findings
                    i = j
                else:
                    i += 1

        # Deduplicate by source IP (keep highest unique_ports finding per source)
        seen_srcs: dict = {}
        for f in findings:
            src = f["source_ip"]
            if src not in seen_srcs or f["unique_ports"] > seen_srcs[src]["unique_ports"]:
                seen_srcs[src] = f

        return list(seen_srcs.values())
