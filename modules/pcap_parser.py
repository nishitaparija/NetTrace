"""
pcap_parser.py
PCAP ingestion, session reconstruction, and metadata extraction.
Author: Nishita Parija
"""

from __future__ import annotations
import ipaddress
from collections import defaultdict, Counter
from datetime import timedelta
from typing import Optional

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Warning: scapy not installed. Run: pip install scapy")


class PcapParser:
    """
    Loads a PCAP/PCAPNG file, optionally filters by subnet,
    and exposes packets and metadata to detection modules.
    """

    def __init__(self, filepath: str, subnet: Optional[str] = None):
        self.filepath = filepath
        self.subnet = subnet
        self._packets: list = []
        self._subnet_obj = None

        if subnet:
            try:
                self._subnet_obj = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                print(f"[!] Invalid subnet '{subnet}' — ignoring subnet filter.")

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def load(self) -> list:
        """Load and optionally filter packets. Returns packet list."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required. Install with: pip install scapy")

        raw = rdpcap(self.filepath)

        if self._subnet_obj:
            filtered = []
            for pkt in raw:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    try:
                        if (ipaddress.ip_address(src) in self._subnet_obj or
                                ipaddress.ip_address(dst) in self._subnet_obj):
                            filtered.append(pkt)
                    except ValueError:
                        continue
            self._packets = filtered
        else:
            self._packets = list(raw)

        return self._packets

    def capture_duration(self) -> str:
        """Return human-readable capture duration (HH:MM:SS)."""
        if not self._packets:
            return "00:00:00"
        try:
            times = [float(p.time) for p in self._packets if hasattr(p, "time")]
            if len(times) < 2:
                return "00:00:00"
            delta = times[-1] - times[0]
            return str(timedelta(seconds=int(delta)))
        except Exception:
            return "unknown"

    def protocol_summary(self) -> dict:
        """Return a dict of {protocol_name: packet_count}."""
        counts: Counter = Counter()
        for pkt in self._packets:
            if ARP in pkt:
                counts["ARP"] += 1
            if IP in pkt:
                if TCP in pkt:
                    counts["TCP"] += 1
                elif UDP in pkt:
                    if DNS in pkt:
                        counts["DNS"] += 1
                    else:
                        counts["UDP"] += 1
                elif ICMP in pkt:
                    counts["ICMP"] += 1
                else:
                    counts["IP(other)"] += 1
        return dict(counts.most_common())

    def metadata(self) -> dict:
        """Return a metadata dict for use in reports."""
        if not self._packets:
            return {}

        try:
            times = [float(p.time) for p in self._packets if hasattr(p, "time")]
            start_ts = times[0] if times else 0
            end_ts   = times[-1] if times else 0
        except Exception:
            start_ts = end_ts = 0

        return {
            "filepath":      self.filepath,
            "total_packets": len(self._packets),
            "duration":      self.capture_duration(),
            "start_time":    start_ts,
            "end_time":      end_ts,
            "protocols":     self.protocol_summary(),
            "subnet_filter": self.subnet,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers used by detectors
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def is_rfc1918(ip: str) -> bool:
        """Return True if the IP address is RFC 1918 private."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False

    @staticmethod
    def group_by_src_dst(packets: list) -> dict:
        """
        Group packets by (src_ip, dst_ip) tuple.
        Returns: { (src, dst): [pkt, ...], ... }
        """
        groups: dict = defaultdict(list)
        for pkt in packets:
            if IP in pkt:
                key = (pkt[IP].src, pkt[IP].dst)
                groups[key].append(pkt)
        return dict(groups)

    @staticmethod
    def tcp_sessions(packets: list) -> dict:
        """
        Reconstruct TCP sessions by (src_ip, src_port, dst_ip, dst_port).
        Returns: { (src_ip, sport, dst_ip, dport): [pkt, ...], ... }
        """
        sessions: dict = defaultdict(list)
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                sessions[key].append(pkt)
        return dict(sessions)
