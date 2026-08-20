"""
AmonStrike — Web Dashboard
Professional security research operations center.

Features:
  - Real-time scan monitoring
  - All findings across all programs
  - Earnings tracker with charts
  - Program leaderboard
  - Submission tracking
  - One-click scan launch
  - Live log streaming via WebSocket

Run: python3 dashboard/app.py
Then: firefox http://localhost:5000
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from flask import (Flask, render_template, jsonify, request,
                   redirect, url_for, Response, stream_with_context)

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(24)

# Global state
_db       = None
_scheduler = None
_scan_logs = []
_log_lock  = threading.Lock()


def get_db():
    global _db
    if _db is None:
        from core.database import Database
        _db = Database()
    return _db


def log_to_dashboard(msg, level="*"):
    with _log_lock:
        _scan_logs.append({
            "ts":    datetime.now().strftime("%H:%M:%S"),
            "msg":   msg,
            "level": level,
        })
        if len(_scan_logs) > 500:
            _scan_logs.pop(0)


# ── API Routes ────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    try:
        stats = get_db().get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/findings")
def api_findings():
    try:
        severity   = request.args.get("severity")
        status     = request.args.get("status")
        program_id = request.args.get("program_id")
        limit      = int(request.args.get("limit", 50))

        findings = get_db().get_findings(
            program_id=program_id,
            severity=severity,
            status=status,
            limit=limit
        )
        return jsonify(findings)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/programs")
def api_programs():
    try:
        programs = get_db().get_top_programs(limit=50)
        return jsonify(programs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/earnings")
def api_earnings():
    try:
        earnings = get_db().get_earnings_summary()
        return jsonify(earnings)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    data = request.json or {}
    url  = data.get("url","").strip()
    mode = data.get("mode","normal")
    mods = data.get("modules","all")

    if not url:
        return jsonify({"error": "URL required"}), 400

    # Validate URL
    if not url.startswith(("http://","https://")):
        url = "http://" + url

    # Launch scan in background thread
    def run():
        log_to_dashboard(f"Starting scan: {url} ({mode})", "+")
        try:
            import subprocess
            cmd = [
                "python3",
                os.path.join(os.path.dirname(os.path.dirname(__file__)),"amonstrike.py"),
                "--url", url,
                "--mode", mode,
                "--no-ui",
            ]
            if mods != "all":
                cmd += ["--modules", mods]

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True
            )
            for line in proc.stdout:
                line = line.strip()
                if line:
                    log_to_dashboard(line)

            proc.wait()
            if proc.returncode == 0:
                log_to_dashboard(f"Scan complete: {url}", "+")
            else:
                log_to_dashboard(f"Scan failed: {url}", "!")
        except Exception as e:
            log_to_dashboard(f"Scan error: {e}", "!")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return jsonify({"status": "started", "url": url, "mode": mode})


@app.route("/api/logs")
def api_logs():
    """Stream scan logs via SSE."""
    def generate():
        last_idx = 0
        while True:
            with _log_lock:
                new_logs = _scan_logs[last_idx:]
                last_idx = len(_scan_logs)

            for entry in new_logs:
                yield f"data: {json.dumps(entry)}\n\n"

            time.sleep(0.5)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":              "no-cache",
            "X-Accel-Buffering":          "no",
            "Access-Control-Allow-Origin": "*",
        }
    )


@app.route("/api/fetch_programs", methods=["POST"])
def api_fetch_programs():
    """Fetch programs from all platforms."""
    def run():
        log_to_dashboard("Fetching programs from all platforms...", "*")
        try:
            from bounty.platform_fetcher import PlatformFetcher
            from bounty.program_ranker   import ProgramRanker

            fetcher  = PlatformFetcher()
            programs = fetcher.fetch_all()
            ranker   = ProgramRanker()
            ranked   = ranker.rank_programs(programs)

            db = get_db()
            for prog in ranked:
                db.upsert_program(prog)
                scope = fetcher.fetch_program_scope(prog)
                if scope:
                    db.upsert_scope(prog["id"], scope)

            log_to_dashboard(f"Fetched and ranked {len(ranked)} programs", "+")
        except Exception as e:
            log_to_dashboard(f"Fetch error: {e}", "!")

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "fetching"})


@app.route("/api/submit_finding", methods=["POST"])
def api_submit_finding():
    """Submit a finding to a bug bounty platform."""
    data        = request.json or {}
    finding_id  = data.get("finding_id")
    program_id  = data.get("program_id")
    platform    = data.get("platform","hackerone")

    if not finding_id or not program_id:
        return jsonify({"error": "finding_id and program_id required"}), 400

    try:
        db       = get_db()
        findings = db.get_findings(limit=1000)
        finding  = next((f for f in findings if f["id"]==finding_id), None)

        if not finding:
            return jsonify({"error": "Finding not found"}), 404

        sub_id = db.create_submission(
            finding_id=finding_id,
            program_id=program_id,
            platform=platform,
            title=finding["title"],
            severity=finding["severity"],
        )

        log_to_dashboard(
            f"Finding submitted to {platform}: {finding['title']}", "+"
        )
        return jsonify({"status": "submitted", "submission_id": sub_id})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── HTML Routes ───────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/findings")
def findings():
    return render_template("findings.html")


@app.route("/programs")
def programs():
    return render_template("programs.html")


@app.route("/earnings")
def earnings():
    return render_template("earnings.html")


@app.route("/scan")
def scan():
    return render_template("scan.html")


@app.route("/submissions")
def submissions():
    return render_template("submissions.html")


def create_app():
    """Create and configure the Flask app."""
    os.makedirs(os.path.join(os.path.dirname(__file__),"templates"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__),"static"), exist_ok=True)
    _create_templates()
    return app


def _create_templates():
    """Create HTML templates."""
    base_html = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AmonStrike Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
:root {
  --bg:      #0D0D1A;
  --panel:   #12121F;
  --border:  #1E1E35;
  --accent:  #C0392B;
  --accent2: #2980B9;
  --text:    #E0E0E0;
  --dim:     #666;
  --green:   #27AE60;
  --yellow:  #E67E22;
  --red:     #C0392B;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--text); font-family:'Segoe UI',monospace; }
.navbar {
  background:var(--panel); border-bottom:1px solid var(--border);
  padding:0 24px; height:56px; display:flex; align-items:center; gap:32px;
  position:sticky; top:0; z-index:100;
}
.navbar .logo { color:var(--accent); font-size:20px; font-weight:900; letter-spacing:2px; }
.navbar a { color:var(--dim); text-decoration:none; font-size:13px; transition:.2s; }
.navbar a:hover, .navbar a.active { color:var(--text); }
.container { max-width:1400px; margin:0 auto; padding:24px; }
.grid-4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }
.grid-2 { display:grid; grid-template-columns:repeat(2,1fr); gap:16px; margin-bottom:24px; }
.card {
  background:var(--panel); border:1px solid var(--border);
  border-radius:8px; padding:20px;
}
.card-title { font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; margin-bottom:12px; }
.stat-value { font-size:36px; font-weight:900; }
.stat-label { font-size:12px; color:var(--dim); margin-top:4px; }
.badge {
  display:inline-block; padding:2px 8px; border-radius:4px;
  font-size:11px; font-weight:700; letter-spacing:1px;
}
.badge-critical { background:#C0392B; color:#fff; }
.badge-high     { background:#E74C3C; color:#fff; }
.badge-medium   { background:#E67E22; color:#fff; }
.badge-low      { background:#27AE60; color:#fff; }
.badge-info     { background:#2980B9; color:#fff; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { background:var(--border); color:var(--dim); padding:10px 12px; text-align:left; font-size:11px; letter-spacing:.5px; }
td { padding:10px 12px; border-bottom:1px solid var(--border); }
tr:hover td { background:rgba(255,255,255,.02); }
.btn {
  display:inline-block; padding:8px 16px; border-radius:6px;
  background:var(--accent); color:#fff; border:none; cursor:pointer;
  font-size:13px; font-weight:600; transition:.2s;
}
.btn:hover { opacity:.8; }
.btn-blue { background:var(--accent2); }
.btn-green { background:var(--green); }
input, select, textarea {
  background:var(--border); border:1px solid #2A2A4A; color:var(--text);
  padding:8px 12px; border-radius:6px; font-size:13px; width:100%;
}
input:focus, select:focus { outline:1px solid var(--accent2); }
.log-panel {
  background:#050510; border:1px solid var(--border); border-radius:8px;
  height:300px; overflow-y:auto; padding:12px; font-family:monospace; font-size:12px;
}
.log-line { margin-bottom:4px; }
.log-plus  { color:var(--green); }
.log-bang  { color:var(--red); }
.log-tilde { color:var(--yellow); }
.log-info  { color:var(--accent2); }
.log-star  { color:var(--dim); }
</style>
</head>
<body>
<nav class="navbar">
  <div class="logo">⚡ AMONSTRIKE</div>
  <a href="/">Dashboard</a>
  <a href="/scan">Scan</a>
  <a href="/findings">Findings</a>
  <a href="/programs">Programs</a>
  <a href="/earnings">Earnings</a>
  <a href="/submissions">Submissions</a>
</nav>
{% block content %}{% endblock %}
<script>
function setBadgeClass(sev) {
  return {CRITICAL:'badge-critical',HIGH:'badge-high',
          MEDIUM:'badge-medium',LOW:'badge-low',INFO:'badge-info'}[sev]||'badge-info';
}
async function api(path) {
  const r = await fetch(path);
  return r.json();
}
</script>
{% block script %}{% endblock %}
</body>
</html>'''

    index_html = '''{% extends "base.html" %}
{% block content %}
<div class="container">
  <h2 style="margin:24px 0 16px;font-size:18px;color:#888">Operations Center</h2>

  <div class="grid-4" id="stats-grid">
    <div class="card"><div class="card-title">Programs</div><div class="stat-value" id="s-programs">—</div></div>
    <div class="card"><div class="card-title">Total Findings</div><div class="stat-value" id="s-findings">—</div></div>
    <div class="card"><div class="card-title">Critical</div><div class="stat-value" style="color:#C0392B" id="s-critical">—</div></div>
    <div class="card"><div class="card-title">Earned (USD)</div><div class="stat-value" style="color:#27AE60" id="s-earned">—</div></div>
    <div class="card"><div class="card-title">Scans Run</div><div class="stat-value" id="s-scans">—</div></div>
    <div class="card"><div class="card-title">Submitted</div><div class="stat-value" id="s-submitted">—</div></div>
    <div class="card"><div class="card-title">High</div><div class="stat-value" style="color:#E74C3C" id="s-high">—</div></div>
    <div class="card"><div class="card-title">New (Unreviewed)</div><div class="stat-value" style="color:#E67E22" id="s-new">—</div></div>
  </div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">Quick Scan</div>
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <input id="q-url" placeholder="http://target.com" style="flex:1"/>
        <select id="q-mode" style="width:120px">
          <option>fast</option><option selected>normal</option>
          <option>deep</option><option>nde</option>
        </select>
        <button class="btn" onclick="quickScan()">▶ Scan</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Platform Actions</div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-blue" onclick="fetchPrograms()">↓ Fetch Programs</button>
        <a href="/programs" class="btn btn-green">📋 Leaderboard</a>
      </div>
      <div id="action-status" style="margin-top:8px;font-size:12px;color:#888"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title" style="display:flex;justify-content:space-between">
      Live Scan Log
      <button class="btn" style="padding:4px 10px;font-size:11px" onclick="clearLog()">Clear</button>
    </div>
    <div class="log-panel" id="log-panel"></div>
  </div>
</div>
{% endblock %}
{% block script %}
<script>
// Load stats
async function loadStats() {
  const s = await api('/api/stats');
  document.getElementById('s-programs').textContent  = s.programs  || 0;
  document.getElementById('s-findings').textContent  = s.findings  || 0;
  document.getElementById('s-critical').textContent  = s.critical  || 0;
  document.getElementById('s-earned').textContent    = '$'+(s.earned_usd||0).toLocaleString();
  document.getElementById('s-scans').textContent     = s.scans     || 0;
  document.getElementById('s-submitted').textContent = s.submitted || 0;
  document.getElementById('s-high').textContent      = s.high      || 0;
  document.getElementById('s-new').textContent       = s.new       || 0;
}
loadStats();
setInterval(loadStats, 10000);

// Live logs
const logPanel = document.getElementById('log-panel');
const evtSrc   = new EventSource('/api/logs');
evtSrc.onmessage = e => {
  const entry  = JSON.parse(e.data);
  const cls    = {'+':'log-plus','!':'log-bang','~':'log-tilde','i':'log-info','*':'log-star'}[entry.level]||'log-star';
  const div    = document.createElement('div');
  div.className = 'log-line ' + cls;
  div.textContent = `[${entry.ts}] [${entry.level}] ${entry.msg}`;
  logPanel.appendChild(div);
  logPanel.scrollTop = logPanel.scrollHeight;
};

async function quickScan() {
  const url  = document.getElementById('q-url').value;
  const mode = document.getElementById('q-mode').value;
  if (!url) return;
  await fetch('/api/scan/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({url, mode})
  });
}

async function fetchPrograms() {
  document.getElementById('action-status').textContent = 'Fetching...';
  await fetch('/api/fetch_programs', {method:'POST'});
  document.getElementById('action-status').textContent = 'Programs fetching in background';
}

function clearLog() { logPanel.innerHTML = ''; }
</script>
{% endblock %}'''

    findings_html = '''{% extends "base.html" %}
{% block content %}
<div class="container">
  <h2 style="margin:24px 0 16px;font-size:18px;color:#888">All Findings</h2>
  <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
    <button class="btn" onclick="loadFindings()">All</button>
    <button class="btn" style="background:#C0392B" onclick="loadFindings('CRITICAL')">Critical</button>
    <button class="btn" style="background:#E74C3C" onclick="loadFindings('HIGH')">High</button>
    <button class="btn" style="background:#E67E22" onclick="loadFindings('MEDIUM')">Medium</button>
    <button class="btn" style="background:#27AE60" onclick="loadFindings('LOW')">Low</button>
  </div>
  <div class="card">
    <table>
      <tr><th>#</th><th>Severity</th><th>Title</th><th>Module</th><th>URL</th><th>Status</th><th>Found</th></tr>
      <tbody id="findings-tbody"></tbody>
    </table>
  </div>
</div>
{% endblock %}
{% block script %}
<script>
async function loadFindings(sev) {
  let url = '/api/findings?limit=100';
  if (sev) url += '&severity=' + sev;
  const findings = await api(url);
  const tbody = document.getElementById('findings-tbody');
  tbody.innerHTML = findings.map((f,i) => `
    <tr>
      <td>${i+1}</td>
      <td><span class="badge ${setBadgeClass(f.severity)}">${f.severity}</span></td>
      <td>${f.title}</td>
      <td><code>${f.module||''}</code></td>
      <td><code style="font-size:11px">${(f.url||'').slice(0,50)}</code></td>
      <td>${f.status||'new'}</td>
      <td>${(f.found_at||'').slice(0,10)}</td>
    </tr>
  `).join('');
}
loadFindings();
</script>
{% endblock %}'''

    programs_html = '''{% extends "base.html" %}
{% block content %}
<div class="container">
  <h2 style="margin:24px 0 16px;font-size:18px;color:#888">Program Leaderboard</h2>
  <div class="card">
    <table>
      <tr><th>#</th><th>Tier</th><th>Score</th><th>Program</th><th>Platform</th><th>Max $</th><th>Auto</th><th>Recommendation</th></tr>
      <tbody id="programs-tbody"></tbody>
    </table>
  </div>
</div>
{% endblock %}
{% block script %}
<script>
const tierColors = {'S-Tier':'#C0392B','A-Tier':'#E67E22','B-Tier':'#27AE60','C-Tier':'#2980B9','D-Tier':'#666'};
async function loadPrograms() {
  const progs = await api('/api/programs');
  const tbody = document.getElementById('programs-tbody');
  tbody.innerHTML = progs.map((p,i) => `
    <tr>
      <td>${i+1}</td>
      <td><span style="color:${tierColors[p.rank_tier]||'#666'};font-weight:700">${p.rank_tier||'—'}</span></td>
      <td>${p.rank_score||0}</td>
      <td><a href="${p.url||'#'}" target="_blank" style="color:#4FC3F7">${p.name}</a></td>
      <td>${p.platform}</td>
      <td>${p.bounty_max > 0 ? '$'+p.bounty_max.toLocaleString() : 'VDP'}</td>
      <td>${p.allows_auto ? '✓' : '✗'}</td>
      <td style="font-size:12px;color:#888">${(p.recommendation||'').slice(0,60)}</td>
    </tr>
  `).join('');
}
loadPrograms();
</script>
{% endblock %}'''

    earnings_html = '''{% extends "base.html" %}
{% block content %}
<div class="container">
  <h2 style="margin:24px 0 16px;font-size:18px;color:#888">Earnings Tracker</h2>
  <div class="grid-4">
    <div class="card"><div class="card-title">Total Earned</div><div class="stat-value" style="color:#27AE60" id="e-total">—</div></div>
    <div class="card"><div class="card-title">Avg Per Finding</div><div class="stat-value" id="e-avg">—</div></div>
    <div class="card"><div class="card-title">Biggest Bounty</div><div class="stat-value" style="color:#E67E22" id="e-max">—</div></div>
    <div class="card"><div class="card-title">Total Payments</div><div class="stat-value" id="e-count">—</div></div>
  </div>
  <div class="grid-2">
    <div class="card"><div class="card-title">By Platform</div><table><tr><th>Platform</th><th>Payments</th><th>Total</th></tr><tbody id="e-platform"></tbody></table></div>
    <div class="card"><div class="card-title">By Severity</div><table><tr><th>Severity</th><th>Count</th><th>Total</th></tr><tbody id="e-severity"></tbody></table></div>
  </div>
</div>
{% endblock %}
{% block script %}
<script>
async function loadEarnings() {
  const data = await api('/api/earnings');
  const s    = data.summary || {};
  document.getElementById('e-total').textContent = '$'+(s.total_usd||0).toLocaleString(undefined,{minimumFractionDigits:2});
  document.getElementById('e-avg').textContent   = '$'+(s.avg_per_finding||0).toFixed(0);
  document.getElementById('e-max').textContent   = '$'+(s.biggest_bounty||0).toLocaleString();
  document.getElementById('e-count').textContent = s.total_payments||0;
  document.getElementById('e-platform').innerHTML = (data.by_platform||[]).map(p=>`<tr><td>${p.platform}</td><td>${p.count}</td><td>$${(p.total||0).toFixed(0)}</td></tr>`).join('');
  document.getElementById('e-severity').innerHTML = (data.by_severity||[]).map(s=>`<tr><td><span class="badge ${setBadgeClass(s.severity)}">${s.severity}</span></td><td>${s.count}</td><td>$${(s.total||0).toFixed(0)}</td></tr>`).join('');
}
loadEarnings();
</script>
{% endblock %}'''

    scan_html = '''{% extends "base.html" %}
{% block content %}
<div class="container">
  <h2 style="margin:24px 0 16px;font-size:18px;color:#888">Launch Scan</h2>
  <div class="grid-2">
    <div class="card">
      <div class="card-title">Scan Configuration</div>
      <div style="display:flex;flex-direction:column;gap:12px">
        <div><label style="font-size:12px;color:#888">Target URL</label><input id="s-url" placeholder="http://target.com" style="margin-top:4px"/></div>
        <div><label style="font-size:12px;color:#888">Scan Mode</label>
          <select id="s-mode" style="margin-top:4px">
            <option value="fast">Fast (~5 min) — Essential checks</option>
            <option value="normal" selected>Normal (~15 min) — All modules</option>
            <option value="deep">Deep (~45 min) — All + NDE + tools</option>
            <option value="nde">NDE — Full autonomous recon</option>
          </select>
        </div>
        <div><label style="font-size:12px;color:#888">Modules (comma-separated or 'all')</label><input id="s-mods" value="all" style="margin-top:4px"/></div>
        <button class="btn" onclick="startScan()" style="width:100%;padding:12px">▶ Start Scan</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Quick Targets</div>
      <div style="display:flex;flex-direction:column;gap:8px">
        <button class="btn btn-blue" onclick="setTarget('http://testphp.vulnweb.com')">testphp.vulnweb.com</button>
        <button class="btn btn-blue" onclick="setTarget('http://testaspnet.vulnweb.com')">testaspnet.vulnweb.com</button>
        <button class="btn btn-blue" onclick="setTarget('http://testasp.vulnweb.com')">testasp.vulnweb.com</button>
        <button class="btn btn-blue" onclick="setTarget('http://demo.testfire.net')">demo.testfire.net</button>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:16px">
    <div class="card-title">Scan Output</div>
    <div class="log-panel" id="scan-log"></div>
  </div>
</div>
{% endblock %}
{% block script %}
<script>
function setTarget(url) { document.getElementById('s-url').value = url; }
async function startScan() {
  const url  = document.getElementById('s-url').value;
  const mode = document.getElementById('s-mode').value.split(' ')[0];
  const mods = document.getElementById('s-mods').value;
  if (!url) return alert('Enter a URL');
  await fetch('/api/scan/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({url,mode,modules:mods})
  });
  addLog(`Scan started: ${url} (${mode})`, '+');
}
const logEl = document.getElementById('scan-log');
const evtSrc = new EventSource('/api/logs');
evtSrc.onmessage = e => {
  const entry = JSON.parse(e.data);
  addLog(`[${entry.ts}] ${entry.msg}`, entry.level);
};
function addLog(msg, level='*') {
  const cls = {'+':'log-plus','!':'log-bang','~':'log-tilde','i':'log-info','*':'log-star'}[level]||'log-star';
  const d   = document.createElement('div');
  d.className = 'log-line ' + cls;
  d.textContent = msg;
  logEl.appendChild(d);
  logEl.scrollTop = logEl.scrollHeight;
}
</script>
{% endblock %}'''

    submissions_html = '''{% extends "base.html" %}
{% block content %}
<div class="container">
  <h2 style="margin:24px 0 16px;font-size:18px;color:#888">Submission Tracker</h2>
  <div class="card">
    <table>
      <tr><th>ID</th><th>Severity</th><th>Title</th><th>Platform</th><th>Status</th><th>Submitted</th><th>Bounty</th></tr>
      <tbody>
        <tr><td colspan="7" style="text-align:center;color:#666;padding:40px">No submissions yet. Submit findings from the Findings page.</td></tr>
      </tbody>
    </table>
  </div>
</div>
{% endblock %}'''

    tmpl_dir = os.path.join(os.path.dirname(__file__), "templates")
    os.makedirs(tmpl_dir, exist_ok=True)

    templates = {
        "base.html":        base_html,
        "index.html":       index_html,
        "findings.html":    findings_html,
        "programs.html":    programs_html,
        "earnings.html":    earnings_html,
        "scan.html":        scan_html,
        "submissions.html": submissions_html,
    }

    for filename, content in templates.items():
        path = os.path.join(tmpl_dir, filename)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(content)


def run_regression_tests():
    """Test dashboard routes without a real server."""
    print("\n=== DASHBOARD REGRESSION TESTS ===")
    passed = failed = 0

    app = create_app()
    client = app.test_client()

    tests = [
        ("GET / returns 200",
         lambda: client.get("/").status_code == 200),
        ("GET /findings returns 200",
         lambda: client.get("/findings").status_code == 200),
        ("GET /programs returns 200",
         lambda: client.get("/programs").status_code == 200),
        ("GET /earnings returns 200",
         lambda: client.get("/earnings").status_code == 200),
        ("GET /scan returns 200",
         lambda: client.get("/scan").status_code == 200),
        ("GET /api/stats returns JSON",
         lambda: client.get("/api/stats").content_type == "application/json"),
        ("GET /api/findings returns JSON",
         lambda: client.get("/api/findings").content_type == "application/json"),
        ("GET /api/programs returns JSON",
         lambda: client.get("/api/programs").content_type == "application/json"),
        ("GET /api/earnings returns JSON",
         lambda: client.get("/api/earnings").content_type == "application/json"),
        ("POST /api/scan/start requires URL",
         lambda: client.post("/api/scan/start",
             json={}, content_type="application/json"
         ).status_code == 400),
        ("POST /api/scan/start with URL returns started",
         lambda: client.post("/api/scan/start",
             json={"url":"http://test.com","mode":"fast"},
             content_type="application/json"
         ).get_json()["status"] == "started"),
        ("Templates created",
         lambda: os.path.exists(
             os.path.join(os.path.dirname(__file__),"templates","index.html")
         )),
        ("POST /api/fetch_programs returns fetching",
         lambda: client.post("/api/fetch_programs").get_json()["status"] == "fetching"),
    ]

    for name, fn in tests:
        try:
            if fn():
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        rp, rf = run_regression_tests()
        sys.exit(0 if rf == 0 else 1)

    print(f"\n  AmonStrike Dashboard starting...")
    print(f"  Open: http://localhost:5000\n")
    create_app()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
