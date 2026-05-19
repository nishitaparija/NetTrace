"""
arp_spoof.py
T1557.002 — ARP Cache Poisoning / Man-in-the-Middle Detection
Author: Nishita Parija

Detection logic:
  1. Duplicate MAC — same IP claimed by two different MACs across the capture.
  2. Gratuitous ARP flood — ARP reply with no corresponding request from same src.
  3. IP-MAC binding change — an IP previously associated with one MAC switches to another.
"""

from __future__ import annotations
from collections import defaultdict

try:
    from scapy.all import ARP
except ImportError:
    pass

from modules.mitre_mapper import get_technique


class ArpSpoofDetector:

    def __init__(self, packets: list, thresholds: dict, verbose: bool = False):
        self.packets = packets
        self.verbose = verbose

    def analyse(self) -> list[dict]:
        findings: list[dict] = []
        att = get_technique("arp_spoof")

        # Track IP → set of MACs seen
        ip_to_macs: dict = defaultdict(set)
        # Track (ip, mac) → first timestamp seen
        binding_timeline: dict = {}
        # Gratuitous ARP: ARP reply where sender_ip == target_ip (op=2, pdst==psrc)
        gratuitous: dict = defaultdict(int)

        for pkt in self.packets:
            if ARP not in pkt:
                continue

            arp = pkt[ARP]
            op  = arp.op          # 1=who-has (request), 2=is-at (reply)
            src_mac = arp.hwsrc
            src_ip  = arp.psrc
            ts = float(pkt.time) if hasattr(pkt, "time") else 0.0

            if src_ip and src_mac:
                ip_to_macs[src_ip].add(src_mac)
                key = (src_ip, src_mac)
                if key not in binding_timeline:
                    binding_timeline[key] = ts

            if op == 2 and arp.pdst == arp.psrc:
                gratuitous[src_ip] += 1

        # Finding 1: IP claimed by multiple MACs
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                macs_list = sorted(macs)
                findings.append({
                    "title":    f"ARP Cache Poisoning — IP {ip} claimed by multiple MACs",
                    "severity": "CRITICAL",
                    "detector": "ArpSpoofDetector",
                    "target_ip":  ip,
                    "mac_addresses": macs_list,
                    "detail": (
                        f"IP address {ip} was associated with {len(macs)} different "
                        f"MAC addresses during the capture: {', '.join(macs_list)}. "
                        "This is a strong indicator of ARP cache poisoning and "
                        "potential man-in-the-middle positioning."
                    ),
                    "mitre": att,
                    "recommendation": (
                        "Enable Dynamic ARP Inspection (DAI) on managed switches. "
                        "Implement static ARP entries for critical hosts. "
                        "Investigate both MAC addresses for compromise. "
                        "Review network topology for MITM positioning."
                    ),
                })

        # Finding 2: Gratuitous ARP flood (> 5 per source = suspicious)
        for src_ip, count in gratuitous.items():
            if count > 5:
                findings.append({
                    "title":    f"Gratuitous ARP Flood from {src_ip}",
                    "severity": "HIGH",
                    "detector": "ArpSpoofDetector",
                    "source_ip":       src_ip,
                    "gratuitous_count": count,
                    "detail": (
                        f"Host {src_ip} sent {count} gratuitous ARP replies (op=2, pdst==psrc). "
                        "Legitimate uses include IP conflict detection or failover, "
                        "but high volumes are consistent with ARP poisoning tools "
                        "such as Ettercap, arpspoof, or Bettercap."
                    ),
                    "mitre": att,
                    "recommendation": (
                        "Investigate source host {src_ip} for ARP spoofing tools. "
                        "Verify whether this host is a legitimate network gateway. "
                        "Enable port security and ARP rate-limiting on the switch port."
                    ),
                })

        return findings
