# NetTrace — Automated PCAP Threat Detection & MITRE ATT&CK Mapping Framework

> **Author:** Nishita Parija  
> **Version:** 1.0.0  
> **Language:** Python 3.8+  
> **Licence:** MIT

---

## Overview

**NetTrace** is a Python-based command-line framework for automated network threat detection through PCAP file analysis. It ingests packet captures, applies a suite of behavioural and statistical detection algorithms, maps confirmed findings to MITRE ATT&CK techniques, extracts Indicators of Compromise (IOCs), and produces structured reports in JSON and HTML formats suitable for direct use in security operations workflows.

NetTrace was built to bridge the gap between raw packet captures and actionable intelligence — reducing the time between evidence collection and incident triage.

---

## Features

| Capability | Detail |
|---|---|
| **8 Detection Modules** | Port scanning, ARP spoofing, DNS exfiltration, beaconing, brute force, ICMP tunnelling, SMB lateral movement, HTTP anomalies |
| **MITRE ATT&CK Mapping** | Every finding tagged with Tactic, Technique ID, and Technique Name |
| **IOC Extraction** | Suspicious IPs, domains, hostnames, User-Agent strings, DNS query strings |
| **CVSS-style Severity** | Critical / High / Medium / Low classification per finding |
| **Dual Report Output** | Structured JSON (SIEM-ingestible) + styled HTML for analyst review |
| **Statistical Beaconing Analysis** | Coefficient of variation analysis on inter-packet timing to identify C2 beaconing |
| **Zero External API Dependency** | Fully offline — no external threat intel feeds required |
| **CLI Interface** | Full argparse CLI with verbosity, threshold tuning, and output format control |

---

## Detected Threat Patterns

| # | Detection | MITRE ATT&CK Technique | Severity |
|---|---|---|---|
| 1 | Port Scanning (SYN/Connect/UDP) | T1046 — Network Service Discovery | High |
| 2 | ARP Cache Poisoning / MITM | T1557.002 — ARP Cache Poisoning | Critical |
| 3 | DNS Exfiltration (long queries, TXT abuse, high entropy) | T1048.003 — Exfil Over DNS | High |
| 4 | C2 Beaconing (statistical regularity analysis) | T1071.001 — Web Protocols | High |
| 5 | SSH / HTTP Brute Force | T1110 — Brute Force | High |
| 6 | ICMP Tunnelling (oversized payload, high frequency) | T1095 — Non-App Layer Protocol | Medium |
| 7 | SMB Lateral Movement | T1021.002 — SMB/Windows Admin Shares | High |
| 8 | Suspicious HTTP (anomalous UA, large POST, clear-text creds) | T1071.001 / T1552.001 | Medium–High |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/nishitaparija/NetTrace.git
cd NetTrace

# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate          # Linux / macOS
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt
```

### Requirements

```
scapy>=2.5.0
pandas>=2.0.0
jinja2>=3.1.0
pyyaml>=6.0
colorama>=0.4.6
tqdm>=4.65.0
```

> **Note:** On Windows, Scapy requires [Npcap](https://npcap.com/) to be installed for live capture. For PCAP file analysis, Npcap is not required.

---

## Usage

### Basic Analysis

```bash
# Analyse a PCAP and generate an HTML report
python netTrace.py -f capture.pcap

# Specify output file and format
python netTrace.py -f capture.pcap -o reports/analysis.html --format html

# JSON output for SIEM ingestion
python netTrace.py -f capture.pcap -o reports/findings.json --format json

# Both formats simultaneously
python netTrace.py -f capture.pcap -o reports/analysis --format both
```

### Advanced Options

```bash
# Verbose output — show all packets matched per detection
python netTrace.py -f capture.pcap --verbose

# Tune detection thresholds
python netTrace.py -f capture.pcap --scan-threshold 20 --beacon-threshold 10 --brute-threshold 5

# Run specific detectors only
python netTrace.py -f capture.pcap --detectors portscan,beaconing,dns

# Filter analysis to a specific subnet
python netTrace.py -f capture.pcap --subnet 192.168.1.0/24

# Extract IOCs only (no full analysis)
python netTrace.py -f capture.pcap --iocs-only
```

### Full Options Reference

```
usage: netTrace.py [-h] -f FILE [-o OUTPUT] [--format {html,json,both}]
                   [--detectors DETECTORS] [--subnet SUBNET]
                   [--scan-threshold N] [--beacon-threshold N]
                   [--brute-threshold N] [--iocs-only] [--verbose] [--quiet]

NetTrace — Automated PCAP Threat Detection Framework

required arguments:
  -f, --file FILE         Path to input PCAP or PCAPNG file

optional arguments:
  -o, --output OUTPUT     Output file path (without extension if --format both)
  --format {html,json,both}
                          Report output format (default: html)
  --detectors DETECTORS   Comma-separated list of detectors to run
                          [portscan, arp, dns, beaconing, bruteforce,
                           icmp, smb, http] (default: all)
  --subnet SUBNET         Restrict analysis to this CIDR subnet
  --scan-threshold N      Unique ports/5s to trigger port scan alert (default: 15)
  --beacon-threshold N    Min connections for beaconing analysis (default: 8)
  --brute-threshold N     Failed auth attempts to trigger brute force (default: 5)
  --iocs-only             Extract IOCs without running full analysis
  --verbose               Print matched packets per finding
  --quiet                 Suppress all output except errors
  -h, --help              Show this help message and exit
```

---

## Sample Output

### Terminal

```
[*] NetTrace v1.0.0 — Automated PCAP Threat Detection Framework
[*] Nishita Parija | github.com/nishitaparija/NetTrace

[+] Loading capture.pcap ...
[+] 48,291 packets loaded | Duration: 00:14:32 | Protocols: TCP, UDP, ICMP, ARP, DNS

[*] Running detection modules ...
    [✓] Port Scan Detector ............. 2 findings
    [✓] ARP Spoof Detector ............. 1 finding
    [✓] DNS Exfiltration Detector ...... 3 findings
    [✓] Beaconing Detector ............. 1 finding
    [✓] Brute Force Detector ........... 1 finding
    [✓] ICMP Tunnel Detector ........... 0 findings
    [✓] SMB Lateral Movement Detector .. 1 finding
    [✓] HTTP Anomaly Detector .......... 2 findings

[*] Extracting IOCs ...
    [✓] 7 suspicious IPs | 4 domains | 3 anomalous User-Agents

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SUMMARY — 11 findings across 8 detectors
  CRITICAL: 1   HIGH: 7   MEDIUM: 2   LOW: 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[+] HTML report saved → reports/analysis.html
[+] JSON report saved → reports/findings.json
```

---

## Project Structure

```
NetTrace/
├── netTrace.py                    # Main entry point / CLI
├── requirements.txt               # Python dependencies
├── config/
│   └── config.yaml                # Tunable thresholds and settings
├── modules/
│   ├── pcap_parser.py             # PCAP ingestion and session reconstruction
│   ├── ioc_extractor.py           # IOC extraction (IPs, domains, UAs)
│   ├── mitre_mapper.py            # MITRE ATT&CK technique mapping
│   ├── reporter.py                # JSON and HTML report generation
│   └── detectors/
│       ├── port_scan.py           # T1046 — port scan detection
│       ├── arp_spoof.py           # T1557.002 — ARP poisoning detection
│       ├── dns_analysis.py        # T1048.003 — DNS exfiltration / tunnelling
│       ├── beaconing.py           # T1071.001 — C2 beaconing (statistical)
│       ├── brute_force.py         # T1110 — SSH/HTTP brute force
│       ├── icmp_tunnel.py         # T1095 — ICMP tunnelling
│       ├── smb_lateral.py         # T1021.002 — SMB lateral movement
│       └── http_anomaly.py        # T1071.001/T1552 — HTTP anomalies
├── templates/
│   └── report.html                # Jinja2 HTML report template
├── reports/                       # Generated reports (git-ignored)
└── samples/                       # Sample PCAP files for testing
```

---

## Detection Methodology

### Beaconing Detection (Statistical Analysis)

C2 beaconing is identified by analysing the inter-arrival times of repeated connections from a single source IP to a single destination IP. A low **Coefficient of Variation (CV)** — defined as `std(intervals) / mean(intervals)` — indicates highly regular, automated communication consistent with beaconing behaviour.

```
CV < 0.3  → HIGH confidence beacon
CV < 0.5  → MEDIUM confidence beacon
CV ≥ 0.5  → Not flagged (likely human-generated traffic)
```

Minimum 8 connections required before statistical analysis is applied to avoid false positives on low-volume traffic.

### DNS Exfiltration Detection

DNS queries are analysed for:
- **Query length > 52 characters** (encoded payload threshold)
- **Shannon entropy > 3.5** on the subdomain portion (high-entropy = likely encoded data)
- **TXT record queries** from internal hosts (common exfil channel)
- **High query frequency** (> 30 queries/minute to same domain)
- **Base64/hex character patterns** in query strings

### Port Scan Detection

A sliding 5-second window tracks unique destination ports per source IP. A source triggering connections to ≥ 15 unique ports within any 5-second window is flagged. SYN packets with no corresponding ACK (half-open/SYN scan pattern) are weighted separately.

---

## Use Cases

- **SOC Alert Triage:** Rapid analysis of PCAP evidence attached to SIEM alerts
- **Incident Response:** First-pass analysis of network captures during active investigations
- **Threat Hunting:** Proactive identification of beaconing, lateral movement, or exfiltration in historical traffic
- **Penetration Test Evidence:** Validate whether conducted attacks generated detectable network artefacts
- **Security Awareness:** Demonstrate to stakeholders what malicious traffic patterns look like in packet data

---

## Tested With

- Wireshark PCAP exports
- `tcpdump` captures
- Malware traffic samples from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)
- CTF challenge PCAP files (PicoCTF, HackTheBox)

---

## Roadmap

- [ ] Live interface capture mode (`-i eth0`)
- [ ] MISP integration for automated IOC submission
- [ ] Suricata rule generation from detected patterns
- [ ] IPv6 support
- [ ] TLS certificate analysis (expired, self-signed, suspicious SNI)
- [ ] SIGMA rule export

---

## Author

**Nishita Parija**  
MSc Cybersecurity Risk Management (1st Class Honours), University of Galway  
[LinkedIn](https://linkedin.com/in/nishitaparija) | [GitHub](https://github.com/nishitaparija)

---

## Licence

MIT Licence — see [LICENSE](LICENSE) for details.
