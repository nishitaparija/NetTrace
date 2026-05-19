"""
mitre_mapper.py
Maps detector findings to MITRE ATT&CK Enterprise techniques.
Author: Nishita Parija
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# Static mapping: detector_key → ATT&CK metadata
# ─────────────────────────────────────────────────────────────────────────────

TECHNIQUE_MAP: dict[str, dict] = {
    # Port Scanning
    "port_scan_syn": {
        "tactic":         "Discovery",
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "sub_technique":  None,
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": (
            "Adversaries may attempt to get a listing of services running on remote "
            "hosts. SYN (half-open) scan: RST returned by closed ports; no ACK sent."
        ),
    },
    "port_scan_connect": {
        "tactic":         "Discovery",
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "sub_technique":  None,
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": (
            "Full TCP connect scan: complete three-way handshake completed for each "
            "probed port. Louder than SYN scan but requires no raw socket privileges."
        ),
    },
    # ARP Spoofing
    "arp_spoof": {
        "tactic":         "Credential Access / Collection",
        "technique_id":   "T1557.002",
        "technique_name": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "sub_technique":  ".002",
        "url": "https://attack.mitre.org/techniques/T1557/002/",
        "description": (
            "Adversaries may poison ARP caches to position themselves between two "
            "communicating hosts, enabling traffic interception and credential theft."
        ),
    },
    # DNS Exfiltration / Tunnelling
    "dns_exfil": {
        "tactic":         "Exfiltration",
        "technique_id":   "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol: DNS",
        "sub_technique":  ".003",
        "url": "https://attack.mitre.org/techniques/T1048/003/",
        "description": (
            "Data is encoded and exfiltrated via DNS query strings or TXT record "
            "responses. High-entropy subdomain labels suggest base64/hex encoding."
        ),
    },
    "dns_tunnel": {
        "tactic":         "Command and Control",
        "technique_id":   "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "sub_technique":  ".004",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
        "description": (
            "Adversaries may communicate using the DNS application layer protocol "
            "to avoid detection and network filtering by blending in with traffic."
        ),
    },
    # Beaconing / C2
    "beaconing": {
        "tactic":         "Command and Control",
        "technique_id":   "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "sub_technique":  ".001",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "description": (
            "Malware beacons to a C2 server at regular intervals. Statistical "
            "analysis of inter-packet timing (low CV) identifies automated traffic."
        ),
    },
    # Brute Force
    "brute_force_ssh": {
        "tactic":         "Credential Access",
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "sub_technique":  None,
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": (
            "Multiple rapid SSH connection attempts from a single source, consistent "
            "with automated credential-stuffing or dictionary-attack tooling."
        ),
    },
    "brute_force_http": {
        "tactic":         "Credential Access",
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "sub_technique":  None,
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": (
            "Repeated HTTP 401 Unauthorized responses to the same resource, "
            "indicating automated form-based or basic-auth credential attacks."
        ),
    },
    # ICMP Tunnelling
    "icmp_tunnel": {
        "tactic":         "Command and Control",
        "technique_id":   "T1095",
        "technique_name": "Non-Application Layer Protocol",
        "sub_technique":  None,
        "url": "https://attack.mitre.org/techniques/T1095/",
        "description": (
            "ICMP payloads exceeding the standard 56-byte ping payload, or high "
            "ICMP frequency, may indicate data tunnelled inside echo request/reply."
        ),
    },
    # SMB Lateral Movement
    "smb_lateral": {
        "tactic":         "Lateral Movement",
        "technique_id":   "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "sub_technique":  ".002",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
        "description": (
            "A single host connecting to SMB (port 445) on multiple unique internal "
            "systems may indicate lateral movement via admin shares or PsExec."
        ),
    },
    # HTTP Anomalies
    "http_suspicious_ua": {
        "tactic":         "Discovery / Initial Access",
        "technique_id":   "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "sub_technique":  ".001",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "description": (
            "HTTP requests carrying User-Agent strings associated with known "
            "scanning, exploitation, or reconnaissance tools."
        ),
    },
    "http_cleartext_creds": {
        "tactic":         "Credential Access",
        "technique_id":   "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials in Files",
        "sub_technique":  ".001",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
        "description": (
            "Credentials (username/password patterns) observed in clear-text HTTP "
            "POST body or URI query parameters."
        ),
    },
    "http_large_post": {
        "tactic":         "Exfiltration",
        "technique_id":   "T1048.001",
        "technique_name": "Exfiltration Over Alternative Protocol: HTTP",
        "sub_technique":  ".001",
        "url": "https://attack.mitre.org/techniques/T1048/001/",
        "description": (
            "Unusually large HTTP POST requests may indicate staged data being "
            "uploaded to an external server as part of an exfiltration operation."
        ),
    },
}


def get_technique(key: str) -> dict:
    """Return ATT&CK metadata for the given detector key, or a generic fallback."""
    return TECHNIQUE_MAP.get(key, {
        "tactic":         "Unknown",
        "technique_id":   "Unknown",
        "technique_name": "Unknown",
        "sub_technique":  None,
        "url":            "https://attack.mitre.org/",
        "description":    "",
    })
