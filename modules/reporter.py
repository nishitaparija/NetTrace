"""
reporter.py
JSON and HTML report generation.
Author: Nishita Parija
"""

from __future__ import annotations
import json
import os
from datetime import datetime
from pathlib import Path
from collections import Counter
from typing import Optional

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

SEVERITY_COLOUR = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#27ae60",
}


class Reporter:

    def __init__(self, findings: list, iocs: dict, pcap_meta: dict, input_file: str):
        self.findings   = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "LOW"), 99))
        self.iocs       = iocs
        self.pcap_meta  = pcap_meta
        self.input_file = input_file
        self.generated  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ─────────────────────────────────────────────────────────────────────────
    # JSON report
    # ─────────────────────────────────────────────────────────────────────────

    def save_json(self, path: str):
        """Write structured JSON report suitable for SIEM ingestion."""
        severity_counts = Counter(f.get("severity", "LOW") for f in self.findings)
        report = {
            "tool":        "NetTrace",
            "version":     "1.0.0",
            "author":      "Nishita Parija",
            "generated":   self.generated,
            "input_file":  self.input_file,
            "pcap_metadata": self.pcap_meta,
            "summary": {
                "total_findings": len(self.findings),
                "critical":       severity_counts.get("CRITICAL", 0),
                "high":           severity_counts.get("HIGH", 0),
                "medium":         severity_counts.get("MEDIUM", 0),
                "low":            severity_counts.get("LOW", 0),
            },
            "findings": self.findings,
            "iocs":      self.iocs,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

    # ─────────────────────────────────────────────────────────────────────────
    # HTML report
    # ─────────────────────────────────────────────────────────────────────────

    def save_html(self, path: str):
        """Generate a styled HTML report from the Jinja2 template."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        template_path = os.path.join(template_dir, "report.html")

        if JINJA2_AVAILABLE and os.path.exists(template_path):
            env = Environment(
                loader=FileSystemLoader(os.path.abspath(template_dir)),
                autoescape=select_autoescape(["html"]),
            )
            template = env.get_template("report.html")
            severity_counts = Counter(f.get("severity", "LOW") for f in self.findings)
            html = template.render(
                tool          = "NetTrace",
                version       = "1.0.0",
                author        = "Nishita Parija",
                generated     = self.generated,
                input_file    = self.input_file,
                pcap_meta     = self.pcap_meta,
                findings      = self.findings,
                iocs          = self.iocs,
                severity_counts = dict(severity_counts),
                severity_colour = SEVERITY_COLOUR,
                total_findings  = len(self.findings),
            )
        else:
            # Fallback: inline HTML if Jinja2 or template not available
            html = self._inline_html()

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    # ─────────────────────────────────────────────────────────────────────────
    # Fallback inline HTML (no Jinja2 required)
    # ─────────────────────────────────────────────────────────────────────────

    def _inline_html(self) -> str:
        sev_counts = Counter(f.get("severity", "LOW") for f in self.findings)
        findings_html = ""
        for f in self.findings:
            sev    = f.get("severity", "LOW")
            colour = SEVERITY_COLOUR.get(sev, "#888")
            mitre  = f.get("mitre", {})
            att_id   = mitre.get("technique_id", "")
            att_name = mitre.get("technique_name", "")
            att_url  = mitre.get("url", "#")
            tactic   = mitre.get("tactic", "")
            findings_html += f"""
            <div class="finding">
              <div class="finding-header" style="border-left: 4px solid {colour}">
                <span class="severity-badge" style="background:{colour}">{sev}</span>
                <strong>{f.get('title','')}</strong>
              </div>
              <div class="finding-body">
                <p>{f.get('detail','')}</p>
                <p><strong>Recommendation:</strong> {f.get('recommendation','')}</p>
                <p><strong>MITRE ATT&CK:</strong>
                  <a href="{att_url}" target="_blank">{att_id} — {att_name}</a>
                  &nbsp;|&nbsp; Tactic: {tactic}
                </p>
              </div>
            </div>"""

        ioc_rows = ""
        for ip_ioc in self.iocs.get("ips", []):
            ioc_rows += f"<tr><td>IP</td><td>{ip_ioc.get('ip')}</td><td>{ip_ioc.get('packet_count')} packets</td></tr>"
        for dom in self.iocs.get("domains", []):
            ioc_rows += f"<tr><td>Domain</td><td>{dom.get('domain')}</td><td>entropy={dom.get('entropy')}</td></tr>"
        for ua in self.iocs.get("user_agents", []):
            ioc_rows += f"<tr><td>User-Agent</td><td colspan='2'>{ua.get('user_agent')}</td></tr>"

        meta = self.pcap_meta
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetTrace Report — {self.input_file}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
  header {{ background: #161b22; border-bottom: 2px solid #21262d; padding: 24px; margin-bottom: 24px; border-radius: 8px; }}
  header h1 {{ color: #58a6ff; font-size: 1.8rem; }}
  header p {{ color: #8b949e; font-size: 0.9rem; margin-top: 4px; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px 24px; flex: 1; min-width: 120px; text-align: center; }}
  .stat .num {{ font-size: 2rem; font-weight: bold; }}
  .stat .label {{ font-size: 0.8rem; color: #8b949e; text-transform: uppercase; }}
  .section-title {{ font-size: 1.2rem; color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 8px; margin: 24px 0 16px; }}
  .finding {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }}
  .finding-header {{ padding: 12px 16px; display: flex; align-items: center; gap: 12px; }}
  .finding-body {{ padding: 12px 16px; border-top: 1px solid #21262d; font-size: 0.9rem; }}
  .finding-body p {{ margin-bottom: 8px; }}
  .severity-badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #fff; white-space: nowrap; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.88rem; }}
  th {{ background: #21262d; color: #8b949e; text-transform: uppercase; font-size: 0.75rem; }}
  a {{ color: #58a6ff; }}
  .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }}
  .meta-item {{ background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 10px 14px; }}
  .meta-item span {{ color: #8b949e; font-size: 0.8rem; display: block; }}
  footer {{ text-align: center; color: #484f58; font-size: 0.8rem; padding: 24px 0; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>&#128270; NetTrace — Threat Detection Report</h1>
    <p>Generated: {self.generated} &nbsp;|&nbsp; Input: {self.input_file} &nbsp;|&nbsp; Author: Nishita Parija</p>
  </header>

  <div class="stats">
    <div class="stat"><div class="num" style="color:#c9d1d9">{len(self.findings)}</div><div class="label">Total Findings</div></div>
    <div class="stat"><div class="num" style="color:#e74c3c">{sev_counts.get('CRITICAL',0)}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num" style="color:#e67e22">{sev_counts.get('HIGH',0)}</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#f39c12">{sev_counts.get('MEDIUM',0)}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num" style="color:#27ae60">{sev_counts.get('LOW',0)}</div><div class="label">Low</div></div>
  </div>

  <div class="meta-grid">
    <div class="meta-item"><span>Packets Analysed</span>{meta.get('total_packets', 'N/A'):,}</div>
    <div class="meta-item"><span>Capture Duration</span>{meta.get('duration', 'N/A')}</div>
    <div class="meta-item"><span>Protocols Detected</span>{', '.join(meta.get('protocols', {}).keys()) or 'N/A'}</div>
    <div class="meta-item"><span>Subnet Filter</span>{meta.get('subnet_filter') or 'None (all traffic)'}</div>
  </div>

  <div class="section-title">Findings ({len(self.findings)})</div>
  {findings_html if findings_html else '<p style="color:#8b949e">No findings detected.</p>'}

  <div class="section-title">Indicators of Compromise</div>
  <table>
    <thead><tr><th>Type</th><th>Indicator</th><th>Detail</th></tr></thead>
    <tbody>{ioc_rows if ioc_rows else '<tr><td colspan="3" style="color:#8b949e">No IOCs extracted.</td></tr>'}</tbody>
  </table>

  <footer>
    <p>NetTrace v1.0.0 &nbsp;|&nbsp; Nishita Parija &nbsp;|&nbsp;
    <a href="https://github.com/nishitaparija/NetTrace">github.com/nishitaparija/NetTrace</a></p>
  </footer>
</div>
</body>
</html>"""
