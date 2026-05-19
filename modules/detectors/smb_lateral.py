"""
smb_lateral.py
T1021.002 — Remote Services: SMB/Windows Admin Shares (Lateral Movement Detection)
Author: Nishita Parija

Detection logic:
  A single internal source IP initiating SMB (port 445) connections to
  multiple unique internal destinations within the capture window.
  Threshold: ≥ 3 unique destination IPs = lateral movement indicator.
"""

from __future__ import annotations
import ipaddress
from collections import defaultdict

try:
    from scapy.all import IP, TCP, Raw
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


class SmbLateralDetector:

    def __init__(self, packets: list, thresholds: dict, verbose: bool = False):
        self.packets   = packets
        self.threshold = 3   # unique SMB destinations
        self.verbose   = verbose

    def analyse(self) -> list[dict]:
        findings: list[dict] = []
        att = get_technique("smb_lateral")

        # Map: src_ip → set of unique SMB destination IPs
        smb_conns: dict = defaultdict(set)
        smb_timestamps: dict = defaultdict(list)

        for pkt in self.packets:
            if IP not in pkt or TCP not in pkt:
                continue

            # SMB uses TCP 445; also capture TCP 139 (NetBIOS)
            if pkt[TCP].dport not in (445, 139):
                continue

            flags  = pkt[TCP].flags
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)

            if not (is_syn and not is_ack):
                continue   # only count SYN packets (new connections)

            src = pkt[IP].src
            dst = pkt[IP].dst
            ts  = float(pkt.time) if hasattr(pkt, "time") else 0.0

            # Only care about internal-to-internal SMB
            if _is_private(src) and _is_private(dst) and src != dst:
                smb_conns[src].add(dst)
                smb_timestamps[src].append(ts)

        for src, destinations in smb_conns.items():
            if len(destinations) >= self.threshold:
                timestamps = sorted(smb_timestamps[src])
                duration   = round(timestamps[-1] - timestamps[0], 1) if len(timestamps) > 1 else 0

                findings.append({
                    "title":    f"SMB Lateral Movement — {src} → {len(destinations)} hosts",
                    "severity": "HIGH",
                    "detector": "SmbLateralDetector",
                    "source_ip":         src,
                    "dest_count":        len(destinations),
                    "dest_ips":          sorted(destinations),
                    "duration_seconds":  duration,
                    "total_connections": len(smb_timestamps[src]),
                    "detail": (
                        f"Internal host {src} initiated SMB connections to "
                        f"{len(destinations)} unique internal destinations "
                        f"over {duration}s: {', '.join(sorted(destinations)[:5])}"
                        f"{'...' if len(destinations) > 5 else ''}. "
                        "This pattern is consistent with lateral movement via SMB "
                        "using tools such as PsExec, CrackMapExec, or Impacket."
                    ),
                    "mitre": att,
                    "recommendation": (
                        f"Isolate {src} from the network immediately for forensic investigation. "
                        "Review Windows Event Logs (4624, 4648, 4776) on destination hosts. "
                        "Check for newly created services or scheduled tasks on target hosts. "
                        "Block inter-VLAN SMB traffic and enforce least-privilege access. "
                        "Audit admin share access across the environment."
                    ),
                })

        return findings
