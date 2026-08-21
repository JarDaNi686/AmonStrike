"""
AmonStrike — Professional Report Generator
Shows REAL evidence: actual data extracted, real credentials found,
working PoC commands, actual HTTP requests/responses.
No "may expose" — only what was confirmed.
"""

import os
import json
import base64
import hashlib
from datetime import datetime
from pathlib import Path


SEV_ORDER  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
SEV_COLOR  = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#16a34a","INFO":"#6b7280"}
SEV_BG     = {"CRITICAL":"#fef2f2","HIGH":"#fff7ed","MEDIUM":"#fffbeb","LOW":"#f0fdf4","INFO":"#f9fafb"}


class ReportGenerator:
    """Generates professional HTML+JSON+PoC reports."""

    def __init__(self, scan_id: str, target: str, output_dir: str):
        self.scan_id    = scan_id
        self.target     = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings   = []
        self.chains     = []
        self.scan_meta  = {}

    def add_finding(self, finding: dict):
        self.findings.append(finding)

    def add_findings(self, findings: list):
        self.findings.extend(findings)

    def add_chain(self, chain: dict):
        self.chains.append(chain)

    def set_meta(self, meta: dict):
        self.scan_meta = meta

    def generate_all(self) -> dict:
        """Generate all report formats."""
        findings = sorted(self.findings,
                         key=lambda f: SEV_ORDER.get(f.get("severity","INFO"),4))

        paths = {
            "html":  self._generate_html(findings),
            "json":  self._generate_json(findings),
            "md":    self._generate_markdown(findings),
        }
        return paths

    def _generate_html(self, findings: list) -> str:
        counts = {s:0 for s in SEV_ORDER}
        for f in findings:
            counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"),0) + 1

        # Build finding cards
        cards_html = ""
        for i, f in enumerate(findings, 1):
            sev     = f.get("severity","INFO")
            color   = SEV_COLOR.get(sev,"#6b7280")
            bg      = SEV_BG.get(sev,"#f9fafb")
            title   = f.get("title","")
            url     = f.get("url","")
            module  = f.get("module","")
            param   = f.get("parameter","")
            payload = f.get("payload","")
            desc    = f.get("description","")
            evidence= f.get("evidence","")
            remediation = f.get("remediation","")
            cve     = f.get("cve","")
            ts      = f.get("timestamp","")

            # Build curl PoC
            curl_poc = self._build_curl_poc(f)

            # Screenshot if available
            shot_html = ""
            if f.get("screenshots"):
                for shot in f["screenshots"][:1]:
                    if shot.get("base64"):
                        shot_html = f'<img src="data:image/png;base64,{shot["base64"]}" style="max-width:100%;border:1px solid #e5e7eb;border-radius:6px;margin-top:8px;" alt="Screenshot"/>'

            cards_html += f"""
<div class="finding" id="finding-{i}" style="border:1px solid {color};border-radius:8px;margin-bottom:20px;overflow:hidden;">
  <div style="background:{color};color:white;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;">
    <div>
      <span style="background:rgba(0,0,0,0.2);padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700;">{sev}</span>
      <span style="font-size:16px;font-weight:600;margin-left:10px;">#{i} {title}</span>
    </div>
    <span style="font-size:12px;opacity:0.9;">{module.upper()}</span>
  </div>
  <div style="padding:16px;background:{bg};">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px;font-size:13px;">
      <div><span style="color:#6b7280;">URL:</span> <a href="{url}" style="color:{color};word-break:break-all;">{url}</a></div>
      {'<div><span style="color:#6b7280;">Parameter:</span> <code style="background:#f3f4f6;padding:1px 4px;border-radius:3px;">' + param + '</code></div>' if param else ''}
      {'<div><span style="color:#6b7280;">CVE/CWE:</span> <span style="background:#fee2e2;color:#991b1b;padding:1px 6px;border-radius:3px;font-size:12px;">' + cve + '</span></div>' if cve else ''}
      <div><span style="color:#6b7280;">Timestamp:</span> {ts[:19]}</div>
    </div>

    <div style="margin-bottom:12px;">
      <strong style="color:#374151;">Description:</strong>
      <p style="margin:6px 0;color:#374151;line-height:1.5;">{desc}</p>
    </div>

    {'<div style="margin-bottom:12px;"><strong style="color:#374151;">Evidence (Confirmed):</strong><pre style="background:#1f2937;color:#f9fafb;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;margin-top:6px;white-space:pre-wrap;">' + evidence.replace('<','&lt;').replace('>','&gt;') + '</pre>' + shot_html + '</div>' if evidence else ''}

    {'<div style="margin-bottom:12px;"><strong style="color:#374151;">Proof of Concept:</strong><pre style="background:#0f172a;color:#7dd3fc;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;margin-top:6px;">' + curl_poc.replace('<','&lt;').replace('>','&gt;') + '</pre></div>' if curl_poc else ''}

    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:6px;padding:12px;">
      <strong style="color:#374151;">&#128736; Remediation:</strong>
      <p style="margin:6px 0;color:#374151;line-height:1.5;">{remediation}</p>
    </div>
  </div>
</div>"""

        # Chains section
        chains_html = ""
        if self.chains:
            chains_html = "<h2 style='color:#dc2626;margin-top:40px;'>⛓️ Vulnerability Chains</h2>"
            for chain in sorted(self.chains, key=lambda c: -c.get("estimated_bounty",0)):
                steps = "".join(f"<li>{s}</li>" for s in chain.get("steps",[]))
                chains_html += f"""
<div style="border:2px solid #dc2626;border-radius:8px;margin-bottom:20px;overflow:hidden;">
  <div style="background:#dc2626;color:white;padding:12px 16px;">
    <strong>{chain.get('name','')}</strong>
    <span style="float:right;">Est. bounty: ${chain.get('estimated_bounty',0):,}</span>
  </div>
  <div style="padding:16px;">
    <p>{chain.get('impact','')}</p>
    <ol style="margin-top:12px;">{steps}</ol>
    {'<pre style="background:#1f2937;color:#f9fafb;padding:12px;border-radius:6px;font-size:11px;margin-top:12px;">' + chain.get('exploit_code','')[:800] + '</pre>' if chain.get('exploit_code') else ''}
  </div>
</div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AmonStrike Report — {self.target}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;color:#1e293b;line-height:1.6; }}
  .container {{ max-width:1100px;margin:0 auto;padding:24px; }}
  pre {{ font-family:'JetBrains Mono','Courier New',monospace; }}
  a {{ text-decoration:none; }}
  .stat {{ text-align:center;background:white;border-radius:10px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.1); }}
  .stat-num {{ font-size:36px;font-weight:700;line-height:1; }}
  .stat-label {{ font-size:13px;color:#6b7280;margin-top:4px; }}
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div style="background:linear-gradient(135deg,#0f172a,#1e3a5f);color:white;border-radius:12px;padding:32px;margin-bottom:24px;">
  <div style="display:flex;justify-content:space-between;align-items:center;">
    <div>
      <div style="font-size:28px;font-weight:700;">⚡ AmonStrike v5.0</div>
      <div style="font-size:16px;opacity:0.8;margin-top:4px;">Security Assessment Report</div>
    </div>
    <div style="text-align:right;font-size:13px;opacity:0.8;">
      <div>Target: <strong>{self.target}</strong></div>
      <div>Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
      <div>Scan ID: {self.scan_id}</div>
    </div>
  </div>
</div>

<!-- Stats -->
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:24px;">
  {''.join(f'<div class="stat"><div class="stat-num" style="color:{SEV_COLOR[s]};">{counts.get(s,0)}</div><div class="stat-label">{s}</div></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"])}
</div>

<!-- Findings -->
<h2 style="margin-bottom:16px;color:#1e293b;">Findings ({len(findings)} total)</h2>
{cards_html}

{chains_html}

<!-- Footer -->
<div style="text-align:center;padding:24px;color:#94a3b8;font-size:12px;">
  Generated by AmonStrike v5.0 — For authorized testing only
</div>
</div>
</body>
</html>"""

        path = self.output_dir / f"report_{self.scan_id}.html"
        path.write_text(html, encoding="utf-8")
        return str(path)

    def _build_curl_poc(self, finding: dict) -> str:
        """Build a working curl command for the finding."""
        url     = finding.get("url","")
        param   = finding.get("parameter","")
        payload = finding.get("payload","")
        module  = finding.get("module","")

        if not url or not payload:
            return ""

        if module in ["sqli","lfi","ssrf","ssti","open_redirect","nosql_injection"]:
            return f'curl -s -k "{url}?{param}={payload}" -H "User-Agent: Mozilla/5.0"'
        elif module in ["xss"]:
            return f'curl -s -k "{url}" --data-urlencode "{param}={payload}"'
        elif module in ["ssrf"]:
            return (f'# SSRF → AWS Metadata\n'
                    f'curl -s -k "{url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/"')
        elif module == "file_upload":
            return (f'# Upload PHP webshell\n'
                    f'curl -s -k -X POST "{url}" \\\n'
                    f'  -F "file=@shell.php;type=application/x-php"\n\n'
                    f'# Execute: curl -s "{url}/shell.php?cmd=id"')
        elif module == "idor":
            next_id = str(int(param)+1) if param.isdigit() else param+'1'; return f'curl -s -k "{url}?{param}={next_id}"'
        elif module in ["csrf"]:
            return (f'# CSRF PoC\n'
                    f'<form action="{url}" method="POST">\n'
                    f'  <input name="{param}" value="{payload}"/>\n'
                    f'  <input type="submit"/>\n'
                    f'</form>')
        else:
            return f'curl -s -k "{url}?{param}={payload}"'

    def _generate_json(self, findings: list) -> str:
        data = {
            "scan_id":   self.scan_id,
            "target":    self.target,
            "timestamp": datetime.now().isoformat(),
            "summary": {s: sum(1 for f in findings if f.get("severity")==s) for s in SEV_ORDER},
            "findings":  findings,
            "chains":    self.chains,
        }
        path = self.output_dir / f"report_{self.scan_id}.json"
        path.write_text(json.dumps(data, indent=2, default=str))
        return str(path)

    def _generate_markdown(self, findings: list) -> str:
        lines = [
            f"# AmonStrike Security Report",
            f"**Target:** {self.target}  ",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
            f"**Total Findings:** {len(findings)}",
            "",
            "## Summary",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        counts = {s: sum(1 for f in findings if f.get("severity")==s) for s in SEV_ORDER}
        for s, c in counts.items():
            lines.append(f"| {s} | {c} |")

        lines += ["", "---", "", "## Findings"]
        for i, f in enumerate(findings, 1):
            lines += [
                f"",
                f"### #{i} [{f.get('severity','')}] {f.get('title','')}",
                f"**URL:** `{f.get('url','')}`  ",
                f"**Module:** {f.get('module','')}  ",
                f"**CWE/CVE:** {f.get('cve','')}",
                f"",
                f"**Description:**",
                f"{f.get('description','')}",
                f"",
                f"**Evidence (Confirmed):**",
                f"```",
                f"{f.get('evidence','')}",
                f"```",
            ]
            poc = self._build_curl_poc(f)
            if poc:
                lines += [f"**PoC:**", f"```bash", poc, f"```"]
            lines += [
                f"",
                f"**Remediation:** {f.get('remediation','')}",
                f"",
                f"---",
            ]

        path = self.output_dir / f"report_{self.scan_id}.md"
        path.write_text("\n".join(lines))
        return str(path)
