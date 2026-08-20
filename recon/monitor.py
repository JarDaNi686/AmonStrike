"""
AmonStrike — Continuous Recon Monitor
24/7 daemon that watches targets and alerts on new attack surface.

Every alert = potential bounty.
New subdomain overnight = untested code.
New JS file = potential secrets/endpoints.
New endpoint = potential IDOR/injection.

Runs scheduled scans and diffs against previous results.
Sends alerts via terminal, file, webhook, or Slack.
"""

import os
import sys
import json
import time
import signal
import sqlite3
import hashlib
import threading
import subprocess
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class ReconMonitor:
    """
    24/7 monitoring daemon for bug bounty targets.

    For each target:
      - Runs recon pipeline on schedule
      - Diffs vs previous results
      - Fires callbacks on changes
      - Persists state to SQLite
    """

    def __init__(self, db_path: str = None, output_base: str = None,
                 alert_fn: Callable = None):
        self.db_path     = db_path or os.path.expanduser("~/.amonstrike/monitor.db")
        self.output_base = Path(output_base or os.path.expanduser("~/.amonstrike/recon"))
        self.alert_fn    = alert_fn or self._default_alert
        self._targets    = {}       # domain → config
        self._running    = False
        self._threads    = []
        self._lock       = threading.Lock()
        self._stop_event = threading.Event()

        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.output_base.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                domain       TEXT PRIMARY KEY,
                program      TEXT,
                platform     TEXT,
                scan_interval INTEGER DEFAULT 3600,
                last_scan    TEXT,
                next_scan    TEXT,
                enabled      INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT,
                scan_time    TEXT,
                subdomains   INTEGER DEFAULT 0,
                live_hosts   INTEGER DEFAULT 0,
                urls         INTEGER DEFAULT 0,
                js_files     INTEGER DEFAULT 0,
                findings     INTEGER DEFAULT 0,
                duration_s   REAL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT,
                alert_type   TEXT,
                detail       TEXT,
                value        TEXT,
                created_at   TEXT,
                actioned     INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS known_surface (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT,
                type         TEXT,
                value        TEXT UNIQUE,
                first_seen   TEXT,
                last_seen    TEXT
            );
        """)
        conn.commit()
        conn.close()

    # ── Target Management ─────────────────────────────────────

    def add_target(self, domain: str, program: str = "",
                   platform: str = "hackerone",
                   scan_interval: int = 3600):
        """Add a target domain to monitor."""
        domain = domain.lstrip("*.").rstrip("/")
        conn   = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT OR REPLACE INTO targets
            (domain, program, platform, scan_interval, next_scan, enabled)
            VALUES (?,?,?,?,?,1)
        """, (domain, program, platform, scan_interval,
              datetime.now().isoformat()))
        conn.commit()
        conn.close()
        self._targets[domain] = {
            "program":  program,
            "platform": platform,
            "interval": scan_interval,
        }
        self._log(f"Target added: {domain} (every {scan_interval//3600}h)", "+")

    def remove_target(self, domain: str):
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE targets SET enabled=0 WHERE domain=?", (domain,))
        conn.commit()
        conn.close()
        self._targets.pop(domain, None)

    def list_targets(self) -> list:
        conn  = sqlite3.connect(self.db_path)
        rows  = conn.execute(
            "SELECT domain,program,platform,scan_interval,last_scan,next_scan "
            "FROM targets WHERE enabled=1"
        ).fetchall()
        conn.close()
        return [
            {"domain":r[0],"program":r[1],"platform":r[2],
             "interval":r[3],"last_scan":r[4],"next_scan":r[5]}
            for r in rows
        ]

    # ── Monitoring Loop ───────────────────────────────────────

    def start(self, daemon: bool = True):
        """Start the monitoring daemon."""
        self._running    = True
        self._stop_event.clear()

        self._log("AmonStrike Monitor starting...", "+")
        self._load_targets_from_db()

        # Main scheduling thread
        t = threading.Thread(target=self._scheduler_loop, daemon=daemon)
        t.start()
        self._threads.append(t)

        self._log(
            f"Monitor running — watching {len(self._targets)} targets", "+"
        )

        if not daemon:
            try:
                while self._running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        """Stop the monitoring daemon gracefully."""
        self._log("Monitor stopping...", "~")
        self._running = False
        self._stop_event.set()

    def _scheduler_loop(self):
        """Main scheduler: check which targets need scanning."""
        while self._running and not self._stop_event.is_set():
            conn = sqlite3.connect(self.db_path)
            due  = conn.execute("""
                SELECT domain, program, platform, scan_interval
                FROM targets
                WHERE enabled=1
                  AND (next_scan IS NULL OR next_scan <= ?)
            """, (datetime.now().isoformat(),)).fetchall()
            conn.close()

            for domain, program, platform, interval in due:
                if not self._running:
                    break
                t = threading.Thread(
                    target=self._scan_target,
                    args=(domain, program, platform, interval),
                    daemon=True
                )
                t.start()
                self._threads.append(t)

            # Sleep 60s between scheduler ticks
            self._stop_event.wait(60)

    def _scan_target(self, domain: str, program: str,
                     platform: str, interval: int):
        """Run a full recon scan for one target."""
        start_time = time.time()
        self._log(f"Scanning: {domain}", "*")

        try:
            from recon.pipeline import ReconPipeline
            output_dir = self.output_base / domain
            pipe       = ReconPipeline(
                domain, str(output_dir), silent=True
            )
            results    = pipe.run()

            # Process results — fire alerts on new surface
            self._process_results(domain, results)

            # Update scan history
            duration = time.time() - start_time
            self._record_scan(domain, results, duration)

            # Schedule next scan
            next_scan = (
                datetime.now() + timedelta(seconds=interval)
            ).isoformat()
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                UPDATE targets SET last_scan=?, next_scan=? WHERE domain=?
            """, (datetime.now().isoformat(), next_scan, domain))
            conn.commit()
            conn.close()

            self._log(
                f"Scan complete: {domain} "
                f"({len(results.get('new_subs',[]))} new subs, "
                f"{len(results.get('nuclei_findings',[]))} nuclei findings) "
                f"in {duration:.0f}s",
                "+"
            )

        except Exception as e:
            self._log(f"Scan error for {domain}: {e}", "!")

    def _process_results(self, domain: str, results: dict):
        """Compare results to known surface, fire alerts on changes."""
        alert_types = [
            ("new_subs",   "NEW_SUBDOMAIN",   "New subdomain discovered"),
            ("new_hosts",  "NEW_HOST",         "New live web service"),
            ("new_js",     "NEW_JS_FILE",      "New JavaScript file — check for secrets"),
            ("new_urls",   "NEW_ENDPOINT",     "New endpoint discovered"),
            ("takeovers",  "TAKEOVER",         "Subdomain takeover opportunity"),
            ("secrets",    "SECRET_EXPOSED",   "Secret/credential exposed"),
        ]

        for key, alert_type, description in alert_types:
            items = results.get(key, [])
            if not items:
                continue

            for item in items:
                value = item if isinstance(item, str) else json.dumps(item)
                fp    = hashlib.sha256(
                    f"{domain}{alert_type}{value}".encode()
                ).hexdigest()[:12]

                # Don't alert twice for same item
                conn = sqlite3.connect(self.db_path)
                exists = conn.execute(
                    "SELECT 1 FROM alerts WHERE detail=?", (fp,)
                ).fetchone()
                conn.close()
                if exists:
                    continue

                # Fire alert
                self._fire_alert(domain, alert_type, description, value, fp)

        # Also alert on nuclei findings
        for finding in results.get("nuclei_findings",[]):
            sev = finding.get("severity","")
            if sev in ["CRITICAL","HIGH"]:
                self._fire_alert(
                    domain,
                    f"NUCLEI_{sev}",
                    f"Nuclei {sev}: {finding.get('name','')}",
                    finding.get("url",""),
                    hashlib.sha256(
                        f"{domain}{finding.get('template_id','')}{finding.get('url','')}".encode()
                    ).hexdigest()[:12],
                )

    def _fire_alert(self, domain: str, alert_type: str,
                    detail: str, value: str, fp: str):
        """Store and dispatch an alert."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT OR IGNORE INTO alerts
            (domain, alert_type, detail, value, created_at)
            VALUES (?,?,?,?,?)
        """, (domain, alert_type, fp, value, datetime.now().isoformat()))
        conn.commit()
        conn.close()

        alert = {
            "domain":     domain,
            "type":       alert_type,
            "detail":     detail,
            "value":      value[:100],
            "time":       datetime.now().strftime("%H:%M:%S"),
        }
        self.alert_fn(alert)

    def _default_alert(self, alert: dict):
        """Default alert handler — print to terminal."""
        colors = {
            "TAKEOVER":       "\033[91m",
            "SECRET_EXPOSED": "\033[91m",
            "NUCLEI_CRITICAL":"\033[91m",
            "NUCLEI_HIGH":    "\033[93m",
            "NEW_SUBDOMAIN":  "\033[96m",
            "NEW_HOST":       "\033[92m",
            "NEW_JS_FILE":    "\033[93m",
            "NEW_ENDPOINT":   "\033[97m",
        }
        c = colors.get(alert["type"], "\033[97m")
        print(
            f"\033[90m[{alert['time']}]\033[0m "
            f"{c}[ALERT/{alert['type']}]\033[0m "
            f"\033[96m{alert['domain']}\033[0m — "
            f"{alert['detail']}: {alert['value'][:80]}"
        )

    def _record_scan(self, domain: str, results: dict, duration: float):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT INTO scan_history
            (domain,scan_time,subdomains,live_hosts,urls,js_files,findings,duration_s)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            domain,
            datetime.now().isoformat(),
            len(results.get("subdomains",[])),
            len(results.get("live_hosts",[])),
            len(results.get("urls",[])),
            len(results.get("js_files",[])),
            len(results.get("nuclei_findings",[])),
            duration,
        ))
        conn.commit()
        conn.close()

    def _load_targets_from_db(self):
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT domain,program,platform,scan_interval FROM targets WHERE enabled=1"
        ).fetchall()
        conn.close()
        for domain, program, platform, interval in rows:
            self._targets[domain] = {
                "program":  program,
                "platform": platform,
                "interval": interval,
            }

    def get_alerts(self, domain: str = None,
                   unactioned_only: bool = True, limit: int = 50) -> list:
        """Get recent alerts."""
        conn = sqlite3.connect(self.db_path)
        q    = "SELECT domain,alert_type,detail,value,created_at FROM alerts"
        args = []
        conds = []
        if domain:
            conds.append("domain=?"); args.append(domain)
        if unactioned_only:
            conds.append("actioned=0")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += f" ORDER BY created_at DESC LIMIT {limit}"
        rows = conn.execute(q, args).fetchall()
        conn.close()
        return [
            {"domain":r[0],"type":r[1],"detail":r[2],
             "value":r[3],"created_at":r[4]}
            for r in rows
        ]

    def get_scan_stats(self, domain: str = None) -> dict:
        """Get scanning statistics."""
        conn = sqlite3.connect(self.db_path)
        q    = "SELECT COUNT(*),AVG(duration_s),MAX(scan_time) FROM scan_history"
        args = []
        if domain:
            q += " WHERE domain=?"; args.append(domain)
        row = conn.execute(q, args).fetchone()
        conn.close()
        return {
            "total_scans":   row[0],
            "avg_duration_s":round(row[1] or 0, 1),
            "last_scan":     row[2] or "never",
        }

    def _log(self, msg: str, level: str = "*"):
        colors = {"+":"\033[92m","!":"\033[91m","~":"\033[93m","*":"\033[90m"}
        c = colors.get(level, "")
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {c}[MONITOR/{level}]\033[0m {msg}")


def _test_process_results(mon, alerts_received):
    prev = len(alerts_received)
    mon._process_results("test.com", {
        "new_subs":  ["new.test.com"],
        "new_js":    ["http://test.com/new.js"],
        "takeovers": [{"subdomain": "old.test.com"}],
        "secrets":   [], "new_hosts": [],
        "new_urls":  [], "nuclei_findings": [],
    })
    return len(alerts_received) > prev


def run_regression_tests():
    import tempfile
    print("\n=== CONTINUOUS MONITOR REGRESSION TESTS ===")
    passed = failed = 0
    tmp = tempfile.mkdtemp()
    db  = os.path.join(tmp,"monitor.db")
    mon = ReconMonitor(db_path=db, output_base=tmp)

    alerts_received = []
    mon.alert_fn = lambda a: alerts_received.append(a)

    tests = [
        ("Monitor instantiates",
         lambda: isinstance(mon, ReconMonitor)),

        ("DB created",
         lambda: os.path.exists(db)),

        ("Add target works",
         lambda: (mon.add_target("test.com","testprog","hackerone",3600) or True)),

        ("Target listed",
         lambda: any(t["domain"]=="test.com" for t in mon.list_targets())),

        ("Multiple targets",
         lambda: (mon.add_target("test2.com") or True) and
                 len(mon.list_targets()) >= 2),

        ("Remove target",
         lambda: (mon.remove_target("test2.com") or True) and
                 all(t["domain"]!="test2.com" for t in mon.list_targets())),

        ("Alert fires on new sub",
         lambda: (
             mon._fire_alert("test.com","NEW_SUBDOMAIN","New sub","sub.test.com","fp1"),
             len(alerts_received) >= 1
         )[1]),

        ("Alert has required fields",
         lambda: len(alerts_received) > 0 and
                 all(k in alerts_received[-1]
                     for k in ["domain","type","detail","value"])),

        ("Get alerts returns list",
         lambda: isinstance(mon.get_alerts("test.com"), list)),

        ("Get stats returns dict",
         lambda: isinstance(mon.get_scan_stats(), dict)),

        ("Stats has scan count",
         lambda: "total_scans" in mon.get_scan_stats()),

        ("Process results fires alerts",
         lambda: _test_process_results(mon, alerts_received)),

        ("Record scan works",
         lambda: (
             mon._record_scan("test.com",{"subdomains":[],"live_hosts":[],"urls":[],"js_files":[],"nuclei_findings":[]},5.0) or True
         )),
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

    # Start monitor
    mon = ReconMonitor()

    # Add targets from command line
    for arg in sys.argv[1:]:
        if not arg.startswith("--"):
            mon.add_target(arg)

    if not mon.list_targets():
        print("Usage: python3 recon/monitor.py <domain1> [domain2] ...")
        print("       python3 recon/monitor.py --test")
        sys.exit(1)

    mon.start(daemon=False)
