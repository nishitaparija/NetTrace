"""
beaconing.py
T1071.001 — C2 Beaconing Detection via Statistical Timing Analysis
Author: Nishita Parija

Detection logic:
  Groups TCP/UDP packets by (src_ip, dst_ip, dst_port).
  For each group with ≥ min_connections events, calculates the inter-arrival
  times and computes the Coefficient of Variation (CV = std / mean).

  Low CV → highly regular, automated traffic → beaconing.
    CV < 0.30 → HIGH confidence
    CV < 0.50 → MEDIUM confidence

  This technique detects periodic C2 callbacks regardless of the protocol
  used (HTTP/S, DNS, raw TCP), as regularity is the key indicator.
"""

from __future__ import annotations
import math
from collections import defaultdict
from statistics import mean, stdev
from typing import Optional

try:
    from scapy.all import IP, TCP, UDP
except ImportError:
    pass

from modules.mitre_mapper import get_technique


def _coefficient_of_variation(intervals: list[float]) -> Optional[float]:
    """Return CV (std/mean) or None if insufficient data."""
    if len(intervals) < 3:
        return None
    m = mean(intervals)
    if m == 0:
        return None
    try:
        s = stdev(intervals)
        return s / m
    except Exception:
        return None


class BeaconingDetector:

    def __init__(self, packets: list, thresholds: dict, verbose: bool = False):
        self.packets       = packets
        self.min_conns     = thresholds.get("beacon_threshold", 8)
        self.verbose       = verbose
        self.cv_high       = 0.30
        self.cv_medium     = 0.50
        self.min_interval  = 5.0   # seconds — ignore sub-5s bursts

    def analyse(self) -> list[dict]:
        findings:  list[dict] = []
        att = get_technique("beaconing")

        # Build timeline per (src, dst, dport)
        timeline: dict = defaultdict(list)
        for pkt in self.packets:
            if IP not in pkt:
                continue
            ts  = float(pkt.time) if hasattr(pkt, "time") else 0.0
            src = pkt[IP].src
            dst = pkt[IP].dst
            if TCP in pkt:
                dport = pkt[TCP].dport
            elif UDP in pkt:
                dport = pkt[UDP].dport
            else:
                continue
            timeline[(src, dst, dport)].append(ts)

        for (src, dst, dport), timestamps in timeline.items():
            if len(timestamps) < self.min_conns:
                continue

            timestamps.sort()
            intervals = [
                timestamps[i+1] - timestamps[i]
                for i in range(len(timestamps) - 1)
                if timestamps[i+1] - timestamps[i] >= self.min_interval
            ]

            if len(intervals) < 3:
                continue

            cv = _coefficient_of_variation(intervals)
            if cv is None:
                continue

            if cv < self.cv_high:
                severity   = "HIGH"
                confidence = "HIGH"
            elif cv < self.cv_medium:
                severity   = "HIGH"
                confidence = "MEDIUM"
            else:
                continue   # not regular enough

            avg_interval = round(mean(intervals), 2)
            findings.append({
                "title":        f"C2 Beaconing — {src} → {dst}:{dport}",
                "severity":     severity,
                "detector":     "BeaconingDetector",
                "source_ip":    src,
                "dest_ip":      dst,
                "dest_port":    dport,
                "connections":  len(timestamps),
                "cv":           round(cv, 4),
                "confidence":   confidence,
                "avg_interval_sec": avg_interval,
                "detail": (
                    f"{src} made {len(timestamps)} connections to {dst}:{dport} "
                    f"with a mean interval of {avg_interval}s and CV of {round(cv, 4)} "
                    f"({confidence} confidence beacon). "
                    "Low coefficient of variation indicates highly automated, "
                    "periodic communication consistent with C2 callback behaviour."
                ),
                "mitre": att,
                "recommendation": (
                    f"Investigate {src} for malware or unauthorised scheduled tasks. "
                    f"Block or investigate outbound connection to {dst}:{dport}. "
                    "Capture and analyse application-layer payload to identify C2 protocol. "
                    "Check destination IP against threat intelligence feeds."
                ),
            })

        # Sort by CV ascending (most regular first)
        findings.sort(key=lambda x: x["cv"])
        return findings[:20]  # cap at 20 findings
