"""
AmonStrike — Report Generator
Generates professional HTML and PDF vulnerability reports.
"""

import os
import json
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#C0392B",
    "HIGH":     "#E74C3C",
    "MEDIUM":   "#E67E22",
    "LOW":      "#27AE60",
    "INFO":     "#2980B9",
}
SEVERITY_BG = {
    "CRITICAL": "#FDEDEC",
    "HIGH":     "#FDEDEC",
    "MEDIUM":   "#FEF9E7",
    "LOW":      "#EAFAF1",
    "INFO":     "#EBF5FB",
}


class ReportGenerator:

    def __init__(self, url, modules, results, session_data, output_dir):
        self.url          = url
        self.modules      = modules
        self.results      = results
        self.session_data = session_data
        self.output_dir   = output_dir

        # Collect all findings sorted by severity
        self.all_findings = []
        for mod_results in results.values():
            self.all_findings.extend(mod_results.get("findings", []))
        self.all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 4))

        # Counts
        self.counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
        for f in self.all_findings:
            sev = f.get("severity", "INFO")
            self.counts[sev] = self.counts.get(sev, 0) + 1

        self.report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self):
        """Generate both HTML and PDF reports."""
        html_path = os.path.join(self.output_dir, "report.html")
        pdf_path  = os.path.join(self.output_dir, "report.pdf")

        html = self._build_html()
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        # Save JSON too
        json_path = os.path.join(self.output_dir, "findings.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "target": self.url,
                "scan_time": self.report_time,
                "summary": self.counts,
                "findings": self.all_findings,
            }, f, indent=2)

        # Try PDF generation
        pdf_generated = False
        try:
            from weasyprint import HTML as WH
            WH(filename=html_path).write_pdf(pdf_path)
            pdf_generated = True
        except Exception:
            try:
                os.system(f"wkhtmltopdf --quiet {html_path} {pdf_path} 2>/dev/null")
                if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 1000:
                    pdf_generated = True
            except Exception:
                pass

        return html_path, pdf_path if pdf_generated else None

    def _build_html(self):
        """Build the complete HTML report."""
        total = len(self.all_findings)
        risk_score = (
            self.counts["CRITICAL"] * 10 +
            self.counts["HIGH"] * 7 +
            self.counts["MEDIUM"] * 4 +
            self.counts["LOW"] * 1
        )
        risk_level = "CRITICAL" if risk_score >= 20 else "HIGH" if risk_score >= 10 else "MEDIUM" if risk_score >= 5 else "LOW" if risk_score >= 1 else "INFO"

        findings_html = ""
        for i, f in enumerate(self.all_findings, 1):
            sev   = f.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev, "#2980B9")
            bg    = SEVERITY_BG.get(sev, "#EBF5FB")
            findings_html += f"""
            <div class="finding" id="finding-{i}" style="border-left: 5px solid {color}; background: {bg};">
                <div class="finding-header">
                    <span class="finding-num">#{i}</span>
                    <span class="severity-badge" style="background:{color}">{sev}</span>
                    <span class="finding-title">{f.get('title','')}</span>
                    <span class="finding-module">[{f.get('module','').upper()}]</span>
                </div>
                <div class="finding-body">
                    <div class="finding-row">
                        <strong>URL:</strong>
                        <code>{f.get('url','')}</code>
                    </div>
                    <div class="finding-row">
                        <strong>Description:</strong>
                        <p>{f.get('description','')}</p>
                    </div>
                    {'<div class="finding-row"><strong>Evidence:</strong><pre>' + str(f.get('evidence','')).replace('<','&lt;').replace('>','&gt;') + '</pre></div>' if f.get('evidence') else ''}
                    {'<div class="finding-row"><strong>Remediation:</strong><p class="remediation">' + f.get('remediation','') + '</p></div>' if f.get('remediation') else ''}
                    {'<div class="finding-row"><strong>Reference:</strong> <code>' + f.get('cve','') + '</code></div>' if f.get('cve') else ''}
                    <div class="finding-meta">
                        Module: {f.get('module','')} &nbsp;|&nbsp;
                        Time: {f.get('timestamp','')[:19]}
                    </div>
                </div>
            </div>"""

        # Module summary rows
        module_rows = ""
        for mod_name in self.modules:
            mod_results = self.results.get(mod_name, {})
            mod_findings = mod_results.get("findings", [])
            counts = {s: 0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
            for f in mod_findings:
                counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"),0) + 1
            status = "✅" if not mod_findings else "⚠️"
            module_rows += f"""
            <tr>
                <td><strong>{mod_name}</strong></td>
                <td>{status} {'No findings' if not mod_findings else f'{len(mod_findings)} finding(s)'}</td>
                <td><span style="color:{SEVERITY_COLORS['CRITICAL']}">{counts['CRITICAL']}</span></td>
                <td><span style="color:{SEVERITY_COLORS['HIGH']}">{counts['HIGH']}</span></td>
                <td><span style="color:{SEVERITY_COLORS['MEDIUM']}">{counts['MEDIUM']}</span></td>
                <td><span style="color:{SEVERITY_COLORS['LOW']}">{counts['LOW']}</span></td>
                <td><span style="color:{SEVERITY_COLORS['INFO']}">{counts['INFO']}</span></td>
            </tr>"""

        risk_color = SEVERITY_COLORS.get(risk_level, "#2980B9")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AmonStrike Security Report — {self.url}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #F5F6FA; color: #2C3E50; font-size: 14px; }}
.page {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}

/* Header */
.report-header {{ background: linear-gradient(135deg, #0D0D1A 0%, #1A1A2E 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 24px; }}
.report-header h1 {{ font-size: 36px; font-weight: 900; letter-spacing: 2px; color: #C0392B; text-shadow: 0 0 20px rgba(192,57,43,0.5); }}
.report-header .subtitle {{ color: #AAAAAA; margin-top: 6px; font-size: 14px; }}
.report-header .target {{ color: #4FC3F7; font-size: 16px; margin-top: 12px; font-family: monospace; }}
.report-meta {{ display: flex; gap: 30px; margin-top: 20px; flex-wrap: wrap; }}
.report-meta span {{ font-size: 13px; color: #AAAAAA; }}
.report-meta strong {{ color: white; }}

/* Risk Score */
.risk-banner {{ background: {risk_color}; color: white; padding: 16px 24px; border-radius: 8px; margin-bottom: 24px; display: flex; align-items: center; gap: 16px; }}
.risk-banner .risk-label {{ font-size: 13px; opacity: 0.85; }}
.risk-banner .risk-value {{ font-size: 28px; font-weight: 900; }}
.risk-banner .risk-score {{ margin-left: auto; font-size: 13px; opacity: 0.85; }}

/* Summary Cards */
.summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }}
.summary-card {{ background: white; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border-top: 4px solid; }}
.summary-card .count {{ font-size: 36px; font-weight: 900; }}
.summary-card .label {{ font-size: 12px; color: #666; margin-top: 4px; font-weight: 600; letter-spacing: 1px; }}

/* Section */
.section {{ background: white; border-radius: 10px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
.section-title {{ font-size: 18px; font-weight: 700; color: #1A1A2E; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 2px solid #F0F0F0; display: flex; align-items: center; gap: 10px; }}

/* Table */
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ background: #1A1A2E; color: white; padding: 10px 12px; text-align: left; font-size: 12px; letter-spacing: 0.5px; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #F0F0F0; }}
tr:hover td {{ background: #F8F9FA; }}

/* Finding Cards */
.finding {{ border-radius: 8px; margin-bottom: 16px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.06); }}
.finding-header {{ padding: 14px 18px; display: flex; align-items: center; gap: 10px; cursor: pointer; }}
.finding-num {{ font-size: 12px; color: #999; min-width: 28px; }}
.severity-badge {{ padding: 3px 10px; border-radius: 4px; color: white; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
.finding-title {{ font-weight: 600; flex: 1; font-size: 14px; }}
.finding-module {{ font-size: 11px; color: #999; font-family: monospace; }}
.finding-body {{ padding: 16px 18px; border-top: 1px solid rgba(0,0,0,0.06); }}
.finding-row {{ margin-bottom: 12px; }}
.finding-row strong {{ display: block; font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
.finding-row p {{ color: #444; line-height: 1.6; }}
.finding-row code {{ font-family: monospace; background: #F5F5F5; padding: 2px 6px; border-radius: 3px; font-size: 12px; word-break: break-all; }}
pre {{ background: #1E1E2E; color: #D4D4D4; padding: 12px; border-radius: 6px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; font-family: 'Courier New', monospace; }}
.remediation {{ background: #F0FFF4; border-left: 3px solid #27AE60; padding: 10px 12px; border-radius: 0 6px 6px 0; color: #1E8449; font-size: 13px; line-height: 1.6; }}
.finding-meta {{ font-size: 11px; color: #999; margin-top: 10px; padding-top: 10px; border-top: 1px solid #F0F0F0; }}

/* TOC */
.toc {{ column-count: 2; column-gap: 20px; }}
.toc-item {{ display: flex; align-items: center; gap: 8px; padding: 5px 0; font-size: 13px; border-bottom: 1px dotted #EEE; break-inside: avoid; }}
.toc-item a {{ color: #2980B9; text-decoration: none; flex: 1; }}
.toc-item a:hover {{ text-decoration: underline; }}

/* Footer */
.report-footer {{ text-align: center; padding: 20px; color: #999; font-size: 12px; margin-top: 30px; }}

/* Filter bar */
.filter-bar {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }}
.filter-btn {{ padding: 6px 16px; border: 2px solid; border-radius: 20px; cursor: pointer; font-size: 12px; font-weight: 600; background: white; transition: all 0.2s; }}
.filter-btn:hover, .filter-btn.active {{ color: white; }}

@media print {{
    body {{ background: white; }}
    .filter-bar {{ display: none; }}
}}
</style>
</head>
<body>
<div class="page">

<!-- Header -->
<div class="report-header">
    <h1>⚡ AMONSTRIKE</h1>
    <div class="subtitle">Security Vulnerability Assessment Report</div>
    <div class="target">🎯 {self.url}</div>
    <div class="report-meta">
        <span><strong>Scan Date:</strong> {self.report_time}</span>
        <span><strong>Modules:</strong> {', '.join(self.modules)}</span>
        <span><strong>Total Findings:</strong> {total}</span>
        <span><strong>Tool:</strong> AmonStrike v1.0 by JarDani</span>
    </div>
</div>

<!-- Risk Banner -->
<div class="risk-banner">
    <div>
        <div class="risk-label">OVERALL RISK LEVEL</div>
        <div class="risk-value">{risk_level}</div>
    </div>
    <div style="flex:1; height:8px; background:rgba(255,255,255,0.3); border-radius:4px; margin: 0 20px;">
        <div style="width:{min(100, risk_score*5)}%; height:100%; background:white; border-radius:4px;"></div>
    </div>
    <div class="risk-score">Risk Score: <strong>{risk_score}</strong></div>
</div>

<!-- Summary Cards -->
<div class="summary-grid">
    <div class="summary-card" style="border-top-color:{SEVERITY_COLORS['CRITICAL']}">
        <div class="count" style="color:{SEVERITY_COLORS['CRITICAL']}">{self.counts['CRITICAL']}</div>
        <div class="label">CRITICAL</div>
    </div>
    <div class="summary-card" style="border-top-color:{SEVERITY_COLORS['HIGH']}">
        <div class="count" style="color:{SEVERITY_COLORS['HIGH']}">{self.counts['HIGH']}</div>
        <div class="label">HIGH</div>
    </div>
    <div class="summary-card" style="border-top-color:{SEVERITY_COLORS['MEDIUM']}">
        <div class="count" style="color:{SEVERITY_COLORS['MEDIUM']}">{self.counts['MEDIUM']}</div>
        <div class="label">MEDIUM</div>
    </div>
    <div class="summary-card" style="border-top-color:{SEVERITY_COLORS['LOW']}">
        <div class="count" style="color:{SEVERITY_COLORS['LOW']}">{self.counts['LOW']}</div>
        <div class="label">LOW</div>
    </div>
    <div class="summary-card" style="border-top-color:{SEVERITY_COLORS['INFO']}">
        <div class="count" style="color:{SEVERITY_COLORS['INFO']}">{self.counts['INFO']}</div>
        <div class="label">INFO</div>
    </div>
</div>

<!-- Module Summary -->
<div class="section">
    <div class="section-title">📊 Module Summary</div>
    <table>
        <tr>
            <th>Module</th><th>Status</th>
            <th style="color:{SEVERITY_COLORS['CRITICAL']}">CRIT</th>
            <th style="color:{SEVERITY_COLORS['HIGH']}">HIGH</th>
            <th style="color:{SEVERITY_COLORS['MEDIUM']}">MED</th>
            <th style="color:{SEVERITY_COLORS['LOW']}">LOW</th>
            <th style="color:{SEVERITY_COLORS['INFO']}">INFO</th>
        </tr>
        {module_rows}
    </table>
</div>

<!-- Table of Contents -->
<div class="section">
    <div class="section-title">📋 Table of Contents</div>
    <div class="toc">
        {''.join(f'<div class="toc-item"><span style="color:{SEVERITY_COLORS.get(f.get(chr(115)+chr(101)+chr(118)+chr(101)+chr(114)+chr(105)+chr(116)+chr(121)),"#2980B9")}">●</span><a href="#finding-{i+1}">{i+1}. {f.get(chr(116)+chr(105)+chr(116)+chr(108)+chr(101),"")}</a><span class="severity-badge" style="background:{SEVERITY_COLORS.get(f.get(chr(115)+chr(101)+chr(118)+chr(101)+chr(114)+chr(105)+chr(116)+chr(121)),"#2980B9")};padding:2px 6px;font-size:10px">{f.get(chr(115)+chr(101)+chr(118)+chr(101)+chr(114)+chr(105)+chr(116)+chr(121),"")}</span></div>' for i, f in enumerate(self.all_findings))}
    </div>
</div>

<!-- Findings -->
<div class="section">
    <div class="section-title">🔍 Vulnerability Findings ({total} total)</div>

    <!-- Filter buttons -->
    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterFindings('ALL')" style="border-color:#666;color:#666">All ({total})</button>
        <button class="filter-btn" onclick="filterFindings('CRITICAL')" style="border-color:{SEVERITY_COLORS['CRITICAL']};color:{SEVERITY_COLORS['CRITICAL']}">Critical ({self.counts['CRITICAL']})</button>
        <button class="filter-btn" onclick="filterFindings('HIGH')" style="border-color:{SEVERITY_COLORS['HIGH']};color:{SEVERITY_COLORS['HIGH']}">High ({self.counts['HIGH']})</button>
        <button class="filter-btn" onclick="filterFindings('MEDIUM')" style="border-color:{SEVERITY_COLORS['MEDIUM']};color:{SEVERITY_COLORS['MEDIUM']}">Medium ({self.counts['MEDIUM']})</button>
        <button class="filter-btn" onclick="filterFindings('LOW')" style="border-color:{SEVERITY_COLORS['LOW']};color:{SEVERITY_COLORS['LOW']}">Low ({self.counts['LOW']})</button>
        <button class="filter-btn" onclick="filterFindings('INFO')" style="border-color:{SEVERITY_COLORS['INFO']};color:{SEVERITY_COLORS['INFO']}">Info ({self.counts['INFO']})</button>
    </div>

    <div id="findings-container">
        {findings_html if findings_html else '<p style="color:#999;text-align:center;padding:40px">No vulnerabilities found. Target appears secure.</p>'}
    </div>
</div>

<!-- Executive Summary -->
<div class="section">
    <div class="section-title">📝 Executive Summary</div>
    <p style="line-height:1.8;color:#444">
        AmonStrike conducted an automated security assessment of <strong>{self.url}</strong> on {self.report_time}.
        The assessment identified <strong>{total} security issues</strong> across {len(self.modules)} test modules.
        {'⚠️ <strong>Immediate action required</strong> — ' + str(self.counts['CRITICAL']) + ' critical and ' + str(self.counts['HIGH']) + ' high severity vulnerabilities were found that require immediate remediation.' if self.counts['CRITICAL'] + self.counts['HIGH'] > 0 else '✅ No critical or high severity issues found.'}
    </p>
    <br>
    <p style="line-height:1.8;color:#444">
        <strong>Severity breakdown:</strong> Critical: {self.counts['CRITICAL']} · High: {self.counts['HIGH']} · Medium: {self.counts['MEDIUM']} · Low: {self.counts['LOW']} · Informational: {self.counts['INFO']}.
        Overall risk score: <strong style="color:{risk_color}">{risk_score} ({risk_level})</strong>.
    </p>
</div>

<!-- Footer -->
<div class="report-footer">
    <p>Generated by <strong>AmonStrike v1.0</strong> — Bug Bounty Reconnaissance Framework by JarDani</p>
    <p style="margin-top:4px">For authorized penetration testing only · github.com/JarDaNi686/AmonStrike</p>
    <p style="margin-top:4px">Report generated: {self.report_time}</p>
</div>

</div>

<script>
function filterFindings(severity) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');

    document.querySelectorAll('.finding').forEach(f => {{
        if (severity === 'ALL') {{
            f.style.display = '';
        }} else {{
            const badge = f.querySelector('.severity-badge');
            f.style.display = badge && badge.textContent === severity ? '' : 'none';
        }}
    }});
}}

// Toggle finding body
document.querySelectorAll('.finding-header').forEach(h => {{
    h.addEventListener('click', () => {{
        const body = h.nextElementSibling;
        body.style.display = body.style.display === 'none' ? '' : 'none';
    }});
}});
</script>
</body>
</html>"""
