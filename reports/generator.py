"""
AmonStrike — Report Generator v2
Professional HTML + PDF vulnerability reports with:
  - Interactive D3.js attack graph
  - CVSS v3.1 scores
  - Bug bounty submission templates
  - Attack chain visualization
  - Executive + technical sections
"""

import os
import json
from datetime import datetime

SEVERITY_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {"CRITICAL": "#C0392B", "HIGH": "#E74C3C",
                   "MEDIUM": "#E67E22", "LOW": "#27AE60", "INFO": "#2980B9"}
SEVERITY_BG     = {"CRITICAL": "#FDEDEC", "HIGH": "#FDEDEC",
                   "MEDIUM": "#FEF9E7", "LOW": "#EAFAF1", "INFO": "#EBF5FB"}

# CVSS v3.1 base scores by severity
CVSS_SCORES = {
    "CRITICAL": "9.0-10.0",
    "HIGH":     "7.0-8.9",
    "MEDIUM":   "4.0-6.9",
    "LOW":      "0.1-3.9",
    "INFO":     "N/A",
}


class ReportGenerator:

    def __init__(self, url, modules, results, session_data, output_dir):
        self.url          = url
        self.modules      = modules
        self.results      = results
        self.session_data = session_data
        self.output_dir   = output_dir
        self.report_time  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Collect + sort all findings
        self.all_findings = []
        for mod_results in results.values():
            self.all_findings.extend(mod_results.get("findings", []))
        self.all_findings.sort(
            key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 4))

        # Counts
        self.counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        for f in self.all_findings:
            self.counts[f.get("severity","INFO")] = \
                self.counts.get(f.get("severity","INFO"),0) + 1

        # Risk score
        self.risk_score = (
            self.counts["CRITICAL"] * 10 + self.counts["HIGH"] * 7 +
            self.counts["MEDIUM"] * 4  + self.counts["LOW"] * 1
        )
        self.risk_level = (
            "CRITICAL" if self.risk_score >= 20 else
            "HIGH"     if self.risk_score >= 10 else
            "MEDIUM"   if self.risk_score >= 5  else
            "LOW"      if self.risk_score >= 1  else "CLEAN"
        )

    def generate(self):
        html_path = os.path.join(self.output_dir, "report.html")
        pdf_path  = os.path.join(self.output_dir, "report.pdf")

        # Save JSON findings
        json_path = os.path.join(self.output_dir, "findings.json")
        with open(json_path, "w") as f:
            json.dump({
                "target":   self.url,
                "scan_time":self.report_time,
                "summary":  self.counts,
                "risk":     {"score": self.risk_score, "level": self.risk_level},
                "findings": self.all_findings,
            }, f, indent=2)

        # Generate HTML
        html = self._build_html()
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        # Save bug bounty templates
        self._save_bounty_templates()

        # Try PDF
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

    def _save_bounty_templates(self):
        """Generate bug bounty submission templates for critical/high findings."""
        templates = []
        for f in self.all_findings:
            if f.get("severity") in ["CRITICAL","HIGH"]:
                template = self._build_bounty_template(f)
                templates.append(template)

        if templates:
            tmpl_path = os.path.join(self.output_dir, "bounty_templates.md")
            with open(tmpl_path, "w") as f:
                f.write("# AmonStrike — Bug Bounty Submission Templates\n\n")
                f.write(f"**Target:** {self.url}\n")
                f.write(f"**Scan Date:** {self.report_time}\n\n")
                f.write("---\n\n")
                for t in templates:
                    f.write(t + "\n\n---\n\n")

    def _build_bounty_template(self, finding):
        """Build a professional bug bounty submission template."""
        sev   = finding.get("severity","MEDIUM")
        title = finding.get("title","Vulnerability")
        desc  = finding.get("description","")
        evid  = finding.get("evidence","")
        rem   = finding.get("remediation","")
        url   = finding.get("url", self.url)
        cve   = finding.get("cve","")
        cvss  = CVSS_SCORES.get(sev, "N/A")

        return f"""## {title}

**Severity:** {sev}
**CVSS v3.1:** {cvss}
**Affected URL:** {url}
{f'**Reference:** {cve}' if cve else ''}

### Summary
{desc}

### Steps to Reproduce
1. Navigate to: `{url}`
2. {evid.split(chr(10))[0] if evid else 'See evidence below'}

### Evidence
```
{evid[:500] if evid else 'See scan report for full evidence'}
```

### Impact
This vulnerability allows an attacker to {self._impact_for_severity(sev)}.

### Remediation
{rem}

### References
- OWASP: https://owasp.org/www-project-web-security-testing-guide/
{f'- {cve}: https://cwe.mitre.org/data/definitions/{cve.replace("CWE-","")}.html' if cve and cve.startswith("CWE") else ''}
"""

    def _impact_for_severity(self, sev):
        impacts = {
            "CRITICAL": "gain full control of the application, access all data, and potentially compromise the underlying server",
            "HIGH":     "access sensitive data, bypass authentication, or significantly impact application functionality",
            "MEDIUM":   "access restricted functionality or expose sensitive information to unauthorized users",
            "LOW":      "gather information that may aid further attacks or cause minor security concerns",
            "INFO":     "gather reconnaissance information about the target",
        }
        return impacts.get(sev, "cause security issues")


    def _build_bounty_cards(self):
        """Build bounty card HTML for top critical/high findings."""
        cards = []
        for f in [x for x in self.all_findings if x.get("severity") in ["CRITICAL","HIGH"]][:5]:
            sev   = f.get("severity","")
            color = SEVERITY_COLORS.get(sev, "#999")
            title = f.get("title","").replace("<","&lt;").replace(">","&gt;")
            cvss  = CVSS_SCORES.get(sev,"N/A")
            url   = f.get("url","")
            desc  = f.get("description","")[:200].replace("<","&lt;").replace(">","&gt;")
            rem   = f.get("remediation","")[:200].replace("<","&lt;").replace(">","&gt;")
            cards.append(
                f'''<div class="bounty-card">
<div class="bounty-title">{title}
  <span class="f-badge" style="background:{color}">{sev}</span>
</div>
<pre class="bounty-template">## {title}

**Severity:** {sev}
**CVSS v3.1:** {cvss}
**URL:** {url}

### Impact
{desc}

### Remediation
{rem}</pre>
</div>'''
            )
        return "\n".join(cards)

    def _build_html(self):
        """Build the complete interactive HTML report."""
        total = len(self.all_findings)
        risk_color = SEVERITY_COLORS.get(self.risk_level, "#2980B9")

        # Build findings HTML
        findings_html = ""
        for i, f in enumerate(self.all_findings, 1):
            sev   = f.get("severity","INFO")
            color = SEVERITY_COLORS.get(sev, "#2980B9")
            bg    = SEVERITY_BG.get(sev, "#EBF5FB")
            cvss  = CVSS_SCORES.get(sev, "N/A")
            findings_html += f"""
<div class="finding" id="finding-{i}" data-severity="{sev}"
     style="border-left:5px solid {color};background:{bg}">
  <div class="finding-header" onclick="toggleFinding({i})">
    <span class="f-num">#{i}</span>
    <span class="f-badge" style="background:{color}">{sev}</span>
    <span class="f-title">{f.get('title','')}</span>
    <span class="f-meta">[{f.get('module','').upper()}] CVSS: {cvss}</span>
    <span class="f-toggle" id="toggle-{i}">▼</span>
  </div>
  <div class="finding-body" id="body-{i}">
    <div class="f-row"><strong>URL:</strong> <code>{f.get('url','')}</code></div>
    <div class="f-row"><strong>Description:</strong><p>{f.get('description','')}</p></div>
    {'<div class="f-row"><strong>Evidence:</strong><pre>' + str(f.get('evidence','')).replace('<','&lt;').replace('>','&gt;') + '</pre></div>' if f.get('evidence') else ''}
    {'<div class="f-row"><strong>Remediation:</strong><p class="remediation">' + f.get('remediation','') + '</p></div>' if f.get('remediation') else ''}
    {'<div class="f-row"><strong>Reference:</strong> <code>' + f.get('cve','') + '</code></div>' if f.get('cve') else ''}
    <div class="f-row f-footer">Module: {f.get('module','')} &nbsp;|&nbsp; {f.get('timestamp','')[:19]}</div>
  </div>
</div>"""

        # Build module table
        module_rows = ""
        for mod in self.modules:
            mod_findings = self.results.get(mod,{}).get("findings",[])
            c = {s:0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
            for mf in mod_findings:
                c[mf.get("severity","INFO")] = c.get(mf.get("severity","INFO"),0)+1
            status = "✅" if not mod_findings else "⚠️"
            module_rows += f"""
<tr>
  <td><strong>{mod}</strong></td>
  <td>{status} {len(mod_findings)} finding(s)</td>
  <td style="color:{SEVERITY_COLORS['CRITICAL']}">{c['CRITICAL']}</td>
  <td style="color:{SEVERITY_COLORS['HIGH']}">{c['HIGH']}</td>
  <td style="color:{SEVERITY_COLORS['MEDIUM']}">{c['MEDIUM']}</td>
  <td style="color:{SEVERITY_COLORS['LOW']}">{c['LOW']}</td>
  <td style="color:{SEVERITY_COLORS['INFO']}">{c['INFO']}</td>
</tr>"""

        # D3.js graph data
        graph_nodes  = []
        graph_links  = []
        node_id_map  = {}

        # Add target node
        graph_nodes.append({"id":0,"label":self.url[:30],"type":"target","size":20})
        node_id_map["target"] = 0

        # Add module nodes
        for i, mod in enumerate(self.modules, 1):
            mod_findings = self.results.get(mod,{}).get("findings",[])
            if mod_findings:
                graph_nodes.append({"id":i,"label":mod,"type":"module",
                                   "size":10+len(mod_findings)*2})
                graph_links.append({"source":0,"target":i,"value":1})
                node_id_map[mod] = i

        # Add finding nodes for critical/high
        node_counter = len(self.modules) + 1
        for f in self.all_findings:
            if f.get("severity") in ["CRITICAL","HIGH"]:
                mod = f.get("module","")
                graph_nodes.append({
                    "id":    node_counter,
                    "label": f.get("title","")[:25],
                    "type":  f.get("severity","").lower(),
                    "size":  15 if f.get("severity")=="CRITICAL" else 12
                })
                source_id = node_id_map.get(mod, 0)
                graph_links.append({"source":source_id,"target":node_counter,"value":2})
                node_counter += 1

        graph_json = json.dumps({"nodes":graph_nodes,"links":graph_links})

        # TOC
        toc_items = "".join([
            f'<div class="toc-item"><span style="color:{SEVERITY_COLORS.get(f.get("severity","INFO"))}">●</span>'
            f'<a href="#finding-{i+1}">{i+1}. {f.get("title","")[:50]}</a>'
            f'<span class="toc-sev" style="background:{SEVERITY_COLORS.get(f.get("severity","INFO"))}">{f.get("severity","")}</span></div>'
            for i, f in enumerate(self.all_findings)
        ])

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AmonStrike Report — {self.url}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#F5F6FA;color:#2C3E50;font-size:14px}}
.page{{max-width:1200px;margin:0 auto;padding:20px}}

/* Header */
.report-header{{background:linear-gradient(135deg,#0D0D1A 0%,#1A1A2E 100%);color:#fff;padding:40px;border-radius:12px;margin-bottom:24px}}
.report-header h1{{font-size:38px;font-weight:900;letter-spacing:3px;color:#C0392B;text-shadow:0 0 20px rgba(192,57,43,0.4)}}
.report-header .subtitle{{color:#AAA;margin-top:6px;font-size:13px}}
.report-header .target{{color:#4FC3F7;font-size:15px;margin-top:12px;font-family:monospace}}
.report-meta{{display:flex;gap:24px;margin-top:20px;flex-wrap:wrap}}
.report-meta span{{font-size:12px;color:#AAA}}
.report-meta strong{{color:#fff}}

/* Risk banner */
.risk-banner{{background:{risk_color};color:#fff;padding:16px 24px;border-radius:8px;margin-bottom:24px;display:flex;align-items:center;gap:16px}}
.risk-label{{font-size:12px;opacity:.85}}
.risk-value{{font-size:30px;font-weight:900}}
.risk-bar-wrap{{flex:1;height:8px;background:rgba(255,255,255,.3);border-radius:4px;margin:0 20px}}
.risk-bar{{height:100%;background:#fff;border-radius:4px;width:{min(100,self.risk_score*5)}%}}
.risk-score{{font-size:13px;opacity:.85}}

/* Summary cards */
.summary-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
.summary-card{{background:#fff;border-radius:10px;padding:20px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.08);border-top:4px solid}}
.summary-card .count{{font-size:38px;font-weight:900}}
.summary-card .label{{font-size:11px;color:#666;margin-top:4px;font-weight:600;letter-spacing:1px}}

/* Sections */
.section{{background:#fff;border-radius:10px;padding:24px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.06)}}
.section-title{{font-size:17px;font-weight:700;color:#1A1A2E;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid #F0F0F0;display:flex;align-items:center;gap:10px}}

/* D3 Graph */
#attack-graph{{width:100%;height:400px;border:1px solid #E0E0E0;border-radius:8px;background:#FAFAFA;overflow:hidden}}
.node circle{{stroke:#fff;stroke-width:2px;cursor:pointer}}
.node text{{font-size:10px;fill:#333;pointer-events:none}}
.link{{stroke:#ccc;stroke-opacity:.6}}
.node-target circle{{fill:#C0392B}}
.node-module circle{{fill:#2980B9}}
.node-critical circle{{fill:#C0392B}}
.node-high circle{{fill:#E74C3C}}
.tooltip{{position:absolute;background:rgba(0,0,0,.8);color:#fff;padding:6px 10px;border-radius:4px;font-size:12px;pointer-events:none;display:none}}

/* Table */
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#1A1A2E;color:#fff;padding:10px 12px;text-align:left;font-size:12px;letter-spacing:.5px}}
td{{padding:10px 12px;border-bottom:1px solid #F0F0F0}}
tr:hover td{{background:#F8F9FA}}

/* Findings */
.finding{{border-radius:8px;margin-bottom:14px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.06)}}
.finding-header{{padding:14px 18px;display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none}}
.f-num{{font-size:11px;color:#999;min-width:30px}}
.f-badge{{padding:3px 10px;border-radius:4px;color:#fff;font-size:11px;font-weight:700;letter-spacing:1px}}
.f-title{{font-weight:600;flex:1;font-size:14px}}
.f-meta{{font-size:11px;color:#999;font-family:monospace}}
.f-toggle{{color:#999;margin-left:8px;font-size:12px}}
.finding-body{{padding:16px 18px;border-top:1px solid rgba(0,0,0,.06)}}
.f-row{{margin-bottom:12px}}
.f-row strong{{display:block;font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}}
.f-row p,.f-row code{{color:#444;line-height:1.6}}
.f-row code{{font-family:monospace;background:#F5F5F5;padding:2px 6px;border-radius:3px;font-size:12px;word-break:break-all}}
pre{{background:#1E1E2E;color:#D4D4D4;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;font-family:'Courier New',monospace}}
.remediation{{background:#F0FFF4;border-left:3px solid #27AE60;padding:10px 12px;border-radius:0 6px 6px 0;color:#1E8449;font-size:13px;line-height:1.6}}
.f-footer{{font-size:11px;color:#999;margin-top:10px;padding-top:10px;border-top:1px solid #F0F0F0}}

/* Filter bar */
.filter-bar{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}}
.filter-btn{{padding:6px 16px;border:2px solid;border-radius:20px;cursor:pointer;font-size:12px;font-weight:600;background:#fff;transition:all .2s}}
.filter-btn.active{{color:#fff}}

/* TOC */
.toc{{columns:2;column-gap:20px}}
.toc-item{{display:flex;align-items:center;gap:8px;padding:4px 0;font-size:13px;border-bottom:1px dotted #EEE;break-inside:avoid}}
.toc-item a{{color:#2980B9;text-decoration:none;flex:1}}
.toc-sev{{padding:2px 6px;border-radius:3px;color:#fff;font-size:10px;font-weight:700}}

/* Bug bounty section */
.bounty-card{{background:#F8F9FA;border:1px solid #E0E0E0;border-radius:8px;padding:16px;margin-bottom:12px}}
.bounty-title{{font-weight:700;color:#1A1A2E;margin-bottom:8px}}
.bounty-template{{font-family:monospace;font-size:12px;background:#fff;padding:10px;border-radius:4px;border:1px solid #E0E0E0;white-space:pre-wrap}}

/* Footer */
.report-footer{{text-align:center;padding:20px;color:#999;font-size:12px;margin-top:30px}}
</style>
</head>
<body>
<div class="page">

<!-- Header -->
<div class="report-header">
  <h1>⚡ AMONSTRIKE</h1>
  <div class="subtitle">Security Vulnerability Assessment Report v2.0</div>
  <div class="target">🎯 {self.url}</div>
  <div class="report-meta">
    <span><strong>Scan Date:</strong> {self.report_time}</span>
    <span><strong>Modules:</strong> {len(self.modules)}</span>
    <span><strong>Total Findings:</strong> {total}</span>
    <span><strong>Tool:</strong> AmonStrike v2.0 by JarDani</span>
  </div>
</div>

<!-- Risk Banner -->
<div class="risk-banner">
  <div>
    <div class="risk-label">OVERALL RISK LEVEL</div>
    <div class="risk-value">{self.risk_level}</div>
  </div>
  <div class="risk-bar-wrap"><div class="risk-bar"></div></div>
  <div class="risk-score">Risk Score: <strong>{self.risk_score}</strong></div>
</div>

<!-- Summary Cards -->
<div class="summary-grid">
  {''.join([f'<div class="summary-card" style="border-top-color:{SEVERITY_COLORS[s]}"><div class="count" style="color:{SEVERITY_COLORS[s]}">{self.counts[s]}</div><div class="label">{s}</div></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])}
</div>

<!-- D3.js Attack Graph -->
<div class="section">
  <div class="section-title">🕸️ Attack Graph — Finding Relationships</div>
  <div id="attack-graph"></div>
  <div class="tooltip" id="tooltip"></div>
  <p style="font-size:12px;color:#999;margin-top:8px;text-align:center">
    Hover over nodes for details. Red = Critical/High. Blue = Module. Drag to rearrange.
  </p>
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
  <div class="section-title">📋 Table of Contents ({total} findings)</div>
  <div class="toc">{toc_items}</div>
</div>

<!-- Findings -->
<div class="section">
  <div class="section-title">🔍 Vulnerability Findings</div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filter('ALL')" style="border-color:#666;color:#666">
      All ({total})</button>
    {''.join([f'<button class="filter-btn" onclick="filter(\'{s}\')" style="border-color:{SEVERITY_COLORS[s]};color:{SEVERITY_COLORS[s]}">{s} ({self.counts[s]})</button>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])}
  </div>
  <div id="findings-container">
    {findings_html or '<p style="color:#999;text-align:center;padding:40px">No vulnerabilities found.</p>'}
  </div>
</div>

<!-- Bug Bounty Templates -->
<div class="section">
  <div class="section-title">💰 Bug Bounty Submission Templates</div>
  <p style="color:#666;margin-bottom:16px;font-size:13px">
    Professional submission templates for Critical and High findings.
    Full templates saved to <code>bounty_templates.md</code>
  </p>
  {self._build_bounty_cards()}
</div>

<!-- Executive Summary -->
<div class="section">
  <div class="section-title">📝 Executive Summary</div>
  <p style="line-height:1.8;color:#444">
    AmonStrike v2.0 conducted an automated security assessment of
    <strong>{self.url}</strong> on {self.report_time}.
    The assessment identified <strong>{total} security issues</strong>
    across {len(self.modules)} test modules.
    {'⚠️ <strong>Immediate action required</strong> — ' + str(self.counts["CRITICAL"]) + ' critical and ' + str(self.counts["HIGH"]) + ' high severity vulnerabilities were found.' if self.counts["CRITICAL"]+self.counts["HIGH"] > 0 else '✅ No critical or high severity issues found.'}
  </p>
  <br>
  <p style="line-height:1.8;color:#444">
    <strong>Overall risk:</strong>
    <strong style="color:{risk_color}">{self.risk_level} (score: {self.risk_score})</strong> —
    Critical: {self.counts['CRITICAL']} ·
    High: {self.counts['HIGH']} ·
    Medium: {self.counts['MEDIUM']} ·
    Low: {self.counts['LOW']} ·
    Info: {self.counts['INFO']}
  </p>
</div>

<!-- Footer -->
<div class="report-footer">
  <p>Generated by <strong>AmonStrike v2.0</strong> — Bug Bounty Recon Framework by JarDani</p>
  <p style="margin-top:4px">For authorized penetration testing only · github.com/JarDaNi686/AmonStrike</p>
  <p style="margin-top:4px">{self.report_time}</p>
</div>
</div>

<!-- D3.js Attack Graph Script -->
<script>
(function() {{
  const graphData = {graph_json};
  const container = document.getElementById('attack-graph');
  const W = container.clientWidth || 800;
  const H = 400;

  const svg = d3.select('#attack-graph').append('svg')
    .attr('width','100%').attr('height', H);

  const g = svg.append('g');

  svg.call(d3.zoom().scaleExtent([0.3,3])
    .on('zoom', e => g.attr('transform', e.transform)));

  const sim = d3.forceSimulation(graphData.nodes)
    .force('link',   d3.forceLink(graphData.links).id(d=>d.id).distance(80))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('x',      d3.forceX(W/2).strength(0.05))
    .force('y',      d3.forceY(H/2).strength(0.05));

  const link = g.append('g').selectAll('line')
    .data(graphData.links).join('line')
    .attr('class','link').attr('stroke-width', d=>d.value);

  const nodeColors = {{
    target:   '#C0392B',
    module:   '#2980B9',
    critical: '#C0392B',
    high:     '#E74C3C',
    medium:   '#E67E22',
    low:      '#27AE60',
  }};

  const node = g.append('g').selectAll('g')
    .data(graphData.nodes).join('g')
    .attr('class', d=>'node node-'+d.type)
    .call(d3.drag()
      .on('start', (e,d) => {{ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
      .on('drag',  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
      .on('end',   (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}));

  node.append('circle')
    .attr('r', d=>d.size||10)
    .attr('fill', d=>nodeColors[d.type]||'#95A5A6')
    .attr('opacity', 0.85);

  node.append('text')
    .attr('dx', d=>(d.size||10)+4).attr('dy','0.35em')
    .text(d=>d.label);

  const tooltip = document.getElementById('tooltip');
  node.on('mouseover', (e,d) => {{
    tooltip.style.display='block';
    tooltip.style.left=e.pageX+10+'px';
    tooltip.style.top=e.pageY-20+'px';
    tooltip.textContent=d.label;
  }}).on('mouseout', () => {{ tooltip.style.display='none'; }});

  sim.on('tick', () => {{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
        .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform', d=>`translate(${{d.x}},${{d.y}})`);
  }});
}})();

// Filter findings
function filter(sev) {{
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(f=>{{
    f.style.display = sev==='ALL'||f.dataset.severity===sev ? '' : 'none';
  }});
}}

// Toggle finding body
function toggleFinding(i) {{
  const body   = document.getElementById('body-'+i);
  const toggle = document.getElementById('toggle-'+i);
  const hidden = body.style.display === 'none';
  body.style.display = hidden ? '' : 'none';
  toggle.textContent = hidden ? '▼' : '▶';
}}
</script>
</body>
</html>"""
