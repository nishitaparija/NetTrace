"""
brute_force.py
T1110 — Brute Force Detection (SSH, HTTP, SMB)
Author: Nishita Parija

Detection logic:
  SSH:  Multiple TCP SYN packets from one source to port 22 within 60s.
  HTTP: Multiple HTTP 401 responses to requests from same source within 60s.
  SMB:  Multiple failed SMB NTLMSSP authentication sequences.
"""

from __future__ import annotations
from collections import defaultdict

try:
    from scapy.all import IP, TCP, Raw
except ImportError:
    pass

from modules.mitre_mapper import get_technique

WINDOW = 60   # seconds


class BruteForceDetector:

    def __init__(self, packets: list, thresholds: dict, verbose: bool = False):
        self.packets   = packets
        self.threshold = thresholds.get("brute_threshold", 5)
        self.verbose   = verbose

    def analyse(self) -> list[dict]:
        findings: list[dict] = []
        findings += self._detect_ssh()
        findings += self._detect_http_401()
        findings += self._detect_smb_auth()
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # SSH brute force
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_ssh(self) -> list[dict]:
        att = get_technique("brute_force_ssh")
        results: list[dict] = []
        # SYN packets to port 22 per source
        ssh_syns: dict = defaultdict(list)

        for pkt in self.packets:
            if IP not in pkt or TCP not in pkt:
                continue
            if pkt[TCP].dport != 22:
                continue
            flags    = pkt[TCP].flags
            is_syn   = bool(flags & 0x02)
            is_ack   = bool(flags & 0x10)
            if is_syn and not is_ack:
                ts  = float(pkt.time) if hasattr(pkt, "time") else 0.0
                dst = pkt[IP].dst
                ssh_syns[(pkt[IP].src, dst)].append(ts)

        for (src, dst), timestamps in ssh_syns.items():
            timestamps.sort()
            # Sliding window
            for i, t0 in enumerate(timestamps):
                window = [t for t in timestamps[i:] if t - t0 <= WINDOW]
                if len(window) >= self.threshold:
                    results.append({
                        "title":       f"SSH Brute Force — {src} → {dst}:22",
                        "severity":    "HIGH",
                        "detector":    "BruteForceDetector",
                        "source_ip":   src,
                        "dest_ip":     dst,
                        "dest_port":   22,
                        "attempts":    len(window),
                        "window_sec":  WINDOW,
                        "attack_type": "SSH Brute Force",
                        "detail": (
                            f"{src} made {len(window)} SSH connection attempts to {dst}:22 "
                            f"within {WINDOW}s (threshold: {self.threshold}). "
                            "Consistent with automated SSH credential-stuffing or "
                            "dictionary-attack tooling (Hydra, Medusa, Ncrack)."
                        ),
                        "mitre": att,
                        "recommendation": (
                            "Block source IP at the firewall. "
                            "Enable fail2ban or equivalent IP-based rate limiting on SSH. "
                            "Disable password authentication — enforce SSH key-based auth only. "
                            "Alert on repeated SSH failures in SIEM."
                        ),
                    })
                    break  # one finding per pair

        return results

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP 401 brute force
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_http_401(self) -> list[dict]:
        att = get_technique("brute_force_http")
        results: list[dict] = []
        http_401: dict = defaultdict(list)

        for pkt in self.packets:
            if IP not in pkt or TCP not in pkt or Raw not in pkt:
                continue
            payload = bytes(pkt[Raw])
            if b"HTTP/1" in payload and b" 401 " in payload:
                ts  = float(pkt.time) if hasattr(pkt, "time") else 0.0
                src = pkt[IP].src  # server
                dst = pkt[IP].dst  # attacker (receiving 401)
                http_401[(dst, src)].append(ts)

        for (attacker, server), timestamps in http_401.items():
            timestamps.sort()
            for i, t0 in enumerate(timestamps):
                window = [t for t in timestamps[i:] if t - t0 <= WINDOW]
                if len(window) >= self.threshold:
                    results.append({
                        "title":       f"HTTP Brute Force — {attacker} → {server}",
                        "severity":    "HIGH",
                        "detector":    "BruteForceDetector",
                        "source_ip":   attacker,
                        "dest_ip":     server,
                        "attempts":    len(window),
                        "window_sec":  WINDOW,
                        "attack_type": "HTTP Authentication Brute Force",
                        "detail": (
                            f"{attacker} received {len(window)} HTTP 401 Unauthorized "
                            f"responses from {server} within {WINDOW}s. "
                            "Consistent with automated HTTP basic-auth or form-based "
                            "credential brute-forcing."
                        ),
                        "mitre": att,
                        "recommendation": (
                            "Implement account lockout after 5 failed attempts. "
                            "Enable CAPTCHA on authentication endpoints. "
                            "Rate-limit authentication requests by IP. "
                            "Investigate attacker IP against threat intelligence feeds."
                        ),
                    })
                    break

        return results

    # ─────────────────────────────────────────────────────────────────────────
    # SMB authentication failure
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_smb_auth(self) -> list[dict]:
        att = get_technique("brute_force_ssh")  # reuse T1110 — same technique
        results: list[dict] = []
        smb_fails: dict = defaultdict(list)

        for pkt in self.packets:
            if IP not in pkt or TCP not in pkt or Raw not in pkt:
                continue
            if pkt[TCP].dport != 445:
                continue
            payload = bytes(pkt[Raw])
            # NTLMSSP_AUTH pattern in SMB2 session setup response with STATUS_LOGON_FAILURE
            if b"NTLMSSP" in payload and b"\x6d\x00\x00\xc0" in payload:
                ts  = float(pkt.time) if hasattr(pkt, "time") else 0.0
                smb_fails[(pkt[IP].src, pkt[IP].dst)].append(ts)

        for (src, dst), timestamps in smb_fails.items():
            timestamps.sort()
            for i, t0 in enumerate(timestamps):
                window = [t for t in timestamps[i:] if t - t0 <= WINDOW]
                if len(window) >= self.threshold:
                    results.append({
                        "title":       f"SMB Authentication Brute Force — {src} → {dst}:445",
                        "severity":    "HIGH",
                        "detector":    "BruteForceDetector",
                        "source_ip":   src,
                        "dest_ip":     dst,
                        "dest_port":   445,
                        "attempts":    len(window),
                        "attack_type": "SMB NTLM Brute Force",
                        "detail": (
                            f"{src} generated {len(window)} SMB NTLMSSP authentication "
                            f"failures against {dst}:445 within {WINDOW}s. "
                            "Consistent with SMB credential brute-forcing tools "
                            "(CrackMapExec, Impacket smbclient)."
                        ),
                        "mitre": att,
                        "recommendation": (
                            "Block SMB from untrusted network segments. "
                            "Enable SMB signing to prevent relay attacks. "
                            "Audit Active Directory for password spray indicators. "
                            "Implement account lockout policy."
                        ),
                    })
                    break

        return results
