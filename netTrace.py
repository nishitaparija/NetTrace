#!/usr/bin/env python3
"""
NetTrace — Automated PCAP Threat Detection & MITRE ATT&CK Mapping Framework
Author : Nishita Parija
Version: 1.0.0
License: MIT

Usage:
    python netTrace.py -f capture.pcap
    python netTrace.py -f capture.pcap -o reports/analysis --format both
    python netTrace.py -f capture.pcap --detectors portscan,beaconing,dns --verbose
"""

import argparse
import sys
import os
import time
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style

from modules.pcap_parser import PcapParser
from modules.ioc_extractor import IocExtractor
from modules.reporter import Reporter
from modules.detectors.port_scan import PortScanDetector
from modules.detectors.arp_spoof import ArpSpoofDetector
from modules.detectors.dns_analysis import DnsAnalysisDetector
from modules.detectors.beaconing import BeaconingDetector
from modules.detectors.brute_force import BruteForceDetector
from modules.detectors.icmp_tunnel import IcmpTunnelDetector
from modules.detectors.smb_lateral import SmbLateralDetector
from modules.detectors.http_anomaly import HttpAnomalyDetector

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
  _   _      _   _____
 | \\ | | ___| |_|_   _| __ __ _  ___ ___
 |  \\| |/ _ \\ __| | || '__/ _` |/ __/ _ \\
 | |\\  |  __/ |_  | || | | (_| | (_|  __/
 |_| \\_|\\___|\\__| |_||_|  \\__,_|\\___\\___|

{Style.RESET_ALL}{Fore.WHITE}  Automated PCAP Threat Detection & MITRE ATT&CK Mapping Framework
  v1.0.0  |  Nishita Parija  |  github.com/nishitaparija/NetTrace
{Style.RESET_ALL}"""

DETECTOR_MAP = {
    "portscan":   PortScanDetector,
    "arp":        ArpSpoofDetector,
    "dns":        DnsAnalysisDetector,
    "beaconing":  BeaconingDetector,
    "bruteforce": BruteForceDetector,
    "icmp":       IcmpTunnelDetector,
    "smb":        SmbLateralDetector,
    "http":       HttpAnomalyDetector,
}

DETECTOR_LABELS = {
    "portscan":   "Port Scan Detector",
    "arp":        "ARP Spoof Detector",
    "dns":        "DNS Exfiltration Detector",
    "beaconing":  "Beaconing Detector",
    "bruteforce": "Brute Force Detector",
    "icmp":       "ICMP Tunnel Detector",
    "smb":        "SMB Lateral Movement Detector",
    "http":       "HTTP Anomaly Detector",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netTrace.py",
        description="NetTrace — Automated PCAP Threat Detection Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-f", "--file", required=True, metavar="FILE",
                   help="Path to input PCAP or PCAPNG file")
    p.add_argument("-o", "--output", metavar="OUTPUT",
                   help="Output file path (omit extension when --format both)")
    p.add_argument("--format", choices=["html", "json", "both"], default="html",
                   help="Report output format (default: html)")
    p.add_argument("--detectors", metavar="DETECTORS",
                   help=("Comma-separated detectors to run.\n"
                         "Choices: " + ", ".join(DETECTOR_MAP.keys()) + "\n"
                         "(default: all)"))
    p.add_argument("--subnet", metavar="CIDR",
                   help="Restrict analysis to this CIDR subnet (e.g. 192.168.1.0/24)")
    p.add_argument("--scan-threshold", type=int, default=15, metavar="N",
                   help="Unique ports/5s to trigger port scan alert (default: 15)")
    p.add_argument("--beacon-threshold", type=int, default=8, metavar="N",
                   help="Min connections for beaconing analysis (default: 8)")
    p.add_argument("--brute-threshold", type=int, default=5, metavar="N",
                   help="Failed auth attempts to trigger brute force alert (default: 5)")
    p.add_argument("--iocs-only", action="store_true",
                   help="Extract IOCs without running full detection analysis")
    p.add_argument("--verbose", action="store_true",
                   help="Print matched packet details per finding")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress all output except errors")
    return p


def resolve_output_path(args) -> dict:
    """Determine output paths based on --output and --format arguments."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = args.output if args.output else f"reports/netTrace_{timestamp}"
    base = str(Path(base).with_suffix(""))  # strip any extension

    paths = {}
    if args.format in ("html", "both"):
        paths["html"] = base + ".html"
    if args.format in ("json", "both"):
        paths["json"] = base + ".json"
    return paths


def print_summary(all_findings: list, quiet: bool):
    """Print a coloured severity summary to stdout."""
    if quiet:
        return
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1

    print(f"\n{Fore.CYAN}{'━' * 60}")
    print(f"  SUMMARY — {len(all_findings)} finding(s) across detectors")
    print(
        f"  {Fore.RED}CRITICAL: {counts['CRITICAL']}   "
        f"{Fore.YELLOW}HIGH: {counts['HIGH']}   "
        f"{Fore.CYAN}MEDIUM: {counts['MEDIUM']}   "
        f"{Fore.GREEN}LOW: {counts['LOW']}"
    )
    print(f"{Fore.CYAN}{'━' * 60}{Style.RESET_ALL}\n")


def run_detectors(packets, selected: list, thresholds: dict,
                  verbose: bool, quiet: bool) -> list:
    """Run each selected detector and collect findings."""
    all_findings = []
    pad = max(len(DETECTOR_LABELS[k]) for k in selected) + 3

    for key in selected:
        label = DETECTOR_LABELS[key]
        if not quiet:
            print(f"    {Fore.BLUE}[~]{Style.RESET_ALL} {label:<{pad}}", end="", flush=True)

        detector = DETECTOR_MAP[key](packets, thresholds, verbose)
        findings = detector.analyse()

        count = len(findings)
        if not quiet:
            colour = Fore.RED if count > 0 else Fore.GREEN
            noun = "finding" if count == 1 else "findings"
            print(f"{colour}{count} {noun}{Style.RESET_ALL}")

        if verbose and findings:
            for f in findings:
                print(f"        {Fore.YELLOW}→ {f.get('title', '')} "
                      f"[{f.get('severity', '')}]{Style.RESET_ALL}")
                if f.get("detail"):
                    print(f"          {f['detail']}")

        all_findings.extend(findings)

    return all_findings


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    # ── Validate input file ──────────────────────────────────────────────────
    pcap_path = Path(args.file)
    if not pcap_path.exists():
        print(f"{Fore.RED}[!] Error: File not found — {args.file}{Style.RESET_ALL}")
        sys.exit(1)
    if pcap_path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        print(f"{Fore.YELLOW}[!] Warning: unexpected file extension "
              f"'{pcap_path.suffix}'. Proceeding anyway.{Style.RESET_ALL}")

    # ── Resolve output paths ─────────────────────────────────────────────────
    output_paths = resolve_output_path(args)
    for p in output_paths.values():
        Path(p).parent.mkdir(parents=True, exist_ok=True)

    # ── Resolve selected detectors ───────────────────────────────────────────
    if args.detectors:
        requested = [d.strip().lower() for d in args.detectors.split(",")]
        invalid = [d for d in requested if d not in DETECTOR_MAP]
        if invalid:
            print(f"{Fore.RED}[!] Unknown detector(s): {', '.join(invalid)}\n"
                  f"    Valid: {', '.join(DETECTOR_MAP.keys())}{Style.RESET_ALL}")
            sys.exit(1)
        selected = requested
    else:
        selected = list(DETECTOR_MAP.keys())

    thresholds = {
        "scan_threshold":   args.scan_threshold,
        "beacon_threshold": args.beacon_threshold,
        "brute_threshold":  args.brute_threshold,
        "subnet":           args.subnet,
    }

    # ── Load PCAP ────────────────────────────────────────────────────────────
    if not args.quiet:
        print(f"{Fore.WHITE}[+] Loading {pcap_path.name} ...{Style.RESET_ALL}")

    t_start = time.time()
    pcap = PcapParser(str(pcap_path), subnet=args.subnet)
    packets = pcap.load()

    if not packets:
        print(f"{Fore.RED}[!] No packets parsed. Is this a valid PCAP file?{Style.RESET_ALL}")
        sys.exit(1)

    if not args.quiet:
        duration = pcap.capture_duration()
        proto_str = ", ".join(pcap.protocol_summary().keys())
        print(f"{Fore.GREEN}[+] {len(packets):,} packets loaded "
              f"| Duration: {duration} "
              f"| Protocols: {proto_str}{Style.RESET_ALL}\n")

    # ── IOC Extraction ───────────────────────────────────────────────────────
    if not args.quiet:
        print(f"{Fore.WHITE}[*] Extracting IOCs ...{Style.RESET_ALL}")

    ioc_extractor = IocExtractor(packets)
    iocs = ioc_extractor.extract()

    if not args.quiet:
        print(f"{Fore.GREEN}    [✓] {len(iocs.get('ips', []))} suspicious IPs | "
              f"{len(iocs.get('domains', []))} domains | "
              f"{len(iocs.get('user_agents', []))} anomalous User-Agents{Style.RESET_ALL}\n")

    if args.iocs_only:
        print("\nExtracted IOCs:")
        for category, values in iocs.items():
            print(f"\n  [{category.upper()}]")
            for v in values:
                print(f"    - {v}")
        sys.exit(0)

    # ── Run Detection ────────────────────────────────────────────────────────
    if not args.quiet:
        print(f"{Fore.WHITE}[*] Running detection modules ...{Style.RESET_ALL}")

    all_findings = run_detectors(packets, selected, thresholds, args.verbose, args.quiet)

    # ── Summary ──────────────────────────────────────────────────────────────
    print_summary(all_findings, args.quiet)

    # ── Generate Reports ─────────────────────────────────────────────────────
    reporter = Reporter(
        findings=all_findings,
        iocs=iocs,
        pcap_meta=pcap.metadata(),
        input_file=str(pcap_path),
    )

    if "html" in output_paths:
        reporter.save_html(output_paths["html"])
        if not args.quiet:
            print(f"{Fore.GREEN}[+] HTML report saved → {output_paths['html']}{Style.RESET_ALL}")

    if "json" in output_paths:
        reporter.save_json(output_paths["json"])
        if not args.quiet:
            print(f"{Fore.GREEN}[+] JSON report saved → {output_paths['json']}{Style.RESET_ALL}")

    elapsed = round(time.time() - t_start, 2)
    if not args.quiet:
        print(f"\n{Fore.WHITE}[*] Analysis completed in {elapsed}s{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
