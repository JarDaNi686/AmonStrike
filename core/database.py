"""
AmonStrike — Database Engine
SQLite-backed persistent storage for:
  - Bug bounty programs
  - Scan targets + scope
  - Vulnerability findings
  - Submission tracking
  - Earnings ledger
  - Researcher reputation

Schema covers every entity a professional bug bounty hunter needs.
"""

import os
import json
import sqlite3
import hashlib
import threading
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "amonstrike.db")


class Database:
    """
    Thread-safe SQLite database.
    Single source of truth for all AmonStrike data.
    """

    _local = threading.local()

    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_schema()

    @contextmanager
    def conn(self):
        """Thread-local connection context manager."""
        if not getattr(self._local, 'connection', None):
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=OFF")  # Disable FK for simplicity
            self._local.connection = conn
        try:
            yield self._local.connection
        except Exception as e:
            try: self._local.connection.rollback()
            except Exception: pass
            raise

    def _init_schema(self):
        """Create all tables if they don't exist."""
        schema = """
        -- ── Bug Bounty Programs ─────────────────────────────────
        CREATE TABLE IF NOT EXISTS programs (
            id              TEXT PRIMARY KEY,
            platform        TEXT NOT NULL,
            name            TEXT NOT NULL,
            handle          TEXT,
            url             TEXT,
            policy_url      TEXT,
            status          TEXT DEFAULT 'active',
            bounty_min      INTEGER DEFAULT 0,
            bounty_max      INTEGER DEFAULT 0,
            currency        TEXT DEFAULT 'USD',
            response_time   INTEGER DEFAULT 0,
            reputation_pts  INTEGER DEFAULT 0,
            allows_auto     INTEGER DEFAULT 0,
            vdp_only        INTEGER DEFAULT 0,
            raw_json        TEXT,
            fetched_at      TEXT,
            updated_at      TEXT,
            rank_score      REAL DEFAULT 0
        );

        -- ── Program Scope ────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS scope (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id      TEXT NOT NULL,
            asset_type      TEXT NOT NULL,
            target          TEXT NOT NULL,
            instruction     TEXT,
            eligible_for_bounty  INTEGER DEFAULT 1,
            eligible_for_submission INTEGER DEFAULT 1,
            severity_limit  TEXT DEFAULT 'all',
            in_scope        INTEGER DEFAULT 1,
            FOREIGN KEY (program_id) REFERENCES programs(id)
        );

        -- ── Scan Targets ─────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS targets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url             TEXT NOT NULL UNIQUE,
            domain          TEXT,
            program_id      TEXT,
            ip_address      TEXT,
            tech_stack      TEXT,
            waf_detected    TEXT,
            last_scanned    TEXT,
            scan_count      INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'pending',
            priority        INTEGER DEFAULT 5,
            notes           TEXT
        );

        -- ── Scans ────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url      TEXT NOT NULL,
            program_id      TEXT,
            mode            TEXT DEFAULT 'normal',
            modules         TEXT,
            started_at      TEXT,
            completed_at    TEXT,
            duration_secs   INTEGER,
            status          TEXT DEFAULT 'running',
            findings_count  INTEGER DEFAULT 0,
            critical_count  INTEGER DEFAULT 0,
            high_count      INTEGER DEFAULT 0,
            output_dir      TEXT,
            nde_nodes       INTEGER DEFAULT 0,
            dead_ends       INTEGER DEFAULT 0
        );

        -- ── Findings ─────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint     TEXT UNIQUE,
            scan_id         INTEGER,
            program_id      TEXT,
            target_url      TEXT NOT NULL,
            module          TEXT,
            title           TEXT NOT NULL,
            severity        TEXT NOT NULL,
            description     TEXT,
            evidence        TEXT,
            remediation     TEXT,
            cve             TEXT,
            cvss_score      REAL,
            cvss_vector     TEXT,
            url             TEXT,
            parameter       TEXT,
            payload         TEXT,
            request         TEXT,
            response        TEXT,
            screenshot_path TEXT,
            poc_path        TEXT,
            status          TEXT DEFAULT 'new',
            duplicate_of    INTEGER,
            submitted_at    TEXT,
            resolved_at     TEXT,
            bounty_amount   REAL DEFAULT 0,
            platform_id     TEXT,
            notes           TEXT,
            found_at        TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (duplicate_of) REFERENCES findings(id)
        );

        -- ── Submissions ──────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS submissions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id      INTEGER NOT NULL,
            program_id      TEXT NOT NULL,
            platform        TEXT NOT NULL,
            platform_ref    TEXT,
            title           TEXT,
            severity        TEXT,
            status          TEXT DEFAULT 'submitted',
            submitted_at    TEXT,
            triaged_at      TEXT,
            resolved_at     TEXT,
            bounty_paid     REAL DEFAULT 0,
            currency        TEXT DEFAULT 'USD',
            response_notes  TEXT,
            report_path     TEXT,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        );

        -- ── Earnings ─────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS earnings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id   INTEGER,
            program_id      TEXT,
            platform        TEXT,
            amount          REAL NOT NULL,
            currency        TEXT DEFAULT 'USD',
            amount_usd      REAL,
            paid_at         TEXT,
            finding_title   TEXT,
            severity        TEXT,
            notes           TEXT,
            FOREIGN KEY (submission_id) REFERENCES submissions(id)
        );

        -- ── Subdomains ───────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS subdomains (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            domain          TEXT NOT NULL,
            subdomain       TEXT NOT NULL UNIQUE,
            ip_address      TEXT,
            source          TEXT,
            status          TEXT DEFAULT 'unknown',
            is_alive        INTEGER DEFAULT 0,
            http_status     INTEGER,
            title           TEXT,
            tech_stack      TEXT,
            takeover_risk   TEXT,
            discovered_at   TEXT
        );

        -- ── Known Vulnerabilities (dedup) ────────────────────────
        CREATE TABLE IF NOT EXISTS known_vulns (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint     TEXT UNIQUE NOT NULL,
            program_id      TEXT,
            title           TEXT,
            severity        TEXT,
            url             TEXT,
            first_seen      TEXT,
            report_id       TEXT,
            status          TEXT
        );

        -- ── Program Statistics ───────────────────────────────────
        CREATE TABLE IF NOT EXISTS program_stats (
            program_id      TEXT PRIMARY KEY,
            total_scans     INTEGER DEFAULT 0,
            total_findings  INTEGER DEFAULT 0,
            submitted       INTEGER DEFAULT 0,
            accepted        INTEGER DEFAULT 0,
            rejected        INTEGER DEFAULT 0,
            total_earned    REAL DEFAULT 0,
            last_activity   TEXT,
            FOREIGN KEY (program_id) REFERENCES programs(id)
        );

        -- ── CVE Tracker ──────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS cve_tracker (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id      INTEGER,
            cve_id          TEXT,
            cve_title       TEXT,
            cvss_score      REAL,
            status          TEXT DEFAULT 'draft',
            submitted_to    TEXT,
            submitted_at    TEXT,
            published_at    TEXT,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        );

        -- ── Indices ──────────────────────────────────────────────
        CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_status     ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_program    ON findings(program_id);
        CREATE INDEX IF NOT EXISTS idx_scope_program       ON scope(program_id);
        CREATE INDEX IF NOT EXISTS idx_submissions_status  ON submissions(status);
        CREATE INDEX IF NOT EXISTS idx_scans_target        ON scans(target_url);
        """

        with self.conn() as c:
            c.executescript(schema)
            c.commit()

    # ── Programs ──────────────────────────────────────────────

    def upsert_program(self, program: dict):
        sql = """
        INSERT INTO programs (
            id, platform, name, handle, url, policy_url, status,
            bounty_min, bounty_max, currency, response_time,
            allows_auto, vdp_only, raw_json, fetched_at, rank_score
        ) VALUES (
            :id, :platform, :name, :handle, :url, :policy_url, :status,
            :bounty_min, :bounty_max, :currency, :response_time,
            :allows_auto, :vdp_only, :raw_json, :fetched_at, :rank_score
        ) ON CONFLICT(id) DO UPDATE SET
            name=excluded.name, status=excluded.status,
            bounty_min=excluded.bounty_min, bounty_max=excluded.bounty_max,
            allows_auto=excluded.allows_auto, rank_score=excluded.rank_score,
            fetched_at=excluded.fetched_at
        """
        with self.conn() as c:
            c.execute(sql, program)
            c.commit()

    def get_top_programs(self, limit=20, min_bounty=0, allows_auto=True):
        sql = """
        SELECT * FROM programs
        WHERE status='active'
          AND bounty_max >= ?
          AND (allows_auto=1 OR ?=0)
          AND vdp_only=0
        ORDER BY rank_score DESC
        LIMIT ?
        """
        with self.conn() as c:
            rows = c.execute(sql, (min_bounty, 1 if allows_auto else 0, limit)).fetchall()
        return [dict(r) for r in rows]

    def upsert_scope(self, program_id: str, scope_items: list):
        with self.conn() as c:
            c.execute("DELETE FROM scope WHERE program_id=?", (program_id,))
            for item in scope_items:
                c.execute("""
                INSERT OR IGNORE INTO scope
                    (program_id, asset_type, target, instruction,
                     eligible_for_bounty, in_scope)
                VALUES (?,?,?,?,?,?)
                """, (
                    program_id,
                    item.get("asset_type","url"),
                    item.get("target",""),
                    item.get("instruction",""),
                    item.get("eligible_for_bounty", 1),
                    item.get("in_scope", 1)
                ))
            c.commit()

    def get_scope(self, program_id: str, in_scope=True):
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM scope WHERE program_id=? AND in_scope=?",
                (program_id, 1 if in_scope else 0)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Scans ─────────────────────────────────────────────────

    def create_scan(self, target_url, program_id=None, mode="normal", modules=None):
        with self.conn() as c:
            cur = c.execute("""
            INSERT INTO scans (target_url, program_id, mode, modules, started_at, status)
            VALUES (?,?,?,?,?,?)
            """, (target_url, program_id, mode,
                  json.dumps(modules or []),
                  datetime.now().isoformat(), "running"))
            scan_id = cur.lastrowid
            c.commit()
        return scan_id

    def complete_scan(self, scan_id, findings_count=0, critical=0, high=0,
                      output_dir=None, nde_nodes=0, dead_ends=0):
        now = datetime.now().isoformat()
        with self.conn() as c:
            c.execute("""
            UPDATE scans SET
                completed_at=?, status='complete',
                findings_count=?, critical_count=?, high_count=?,
                output_dir=?, nde_nodes=?, dead_ends=?
            WHERE id=?
            """, (now, findings_count, critical, high,
                  output_dir, nde_nodes, dead_ends, scan_id))
            c.commit()

    # ── Findings ──────────────────────────────────────────────

    def fingerprint(self, finding: dict) -> str:
        """Generate deduplication fingerprint for a finding."""
        key = "|".join([
            finding.get("title",""),
            finding.get("url",""),
            finding.get("parameter",""),
            finding.get("severity",""),
        ])
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def save_finding(self, finding: dict, scan_id=None, program_id=None):
        fp = self.fingerprint(finding)
        with self.conn() as c:
            # Check if duplicate
            existing = c.execute(
                "SELECT id FROM findings WHERE fingerprint=?", (fp,)
            ).fetchone()

            if existing:
                return existing[0], True  # (id, is_duplicate)

            cur = c.execute("""
            INSERT INTO findings (
                fingerprint, scan_id, program_id, target_url, module,
                title, severity, description, evidence, remediation,
                cve, url, status, found_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                fp, scan_id, program_id,
                finding.get("url",""),
                finding.get("module",""),
                finding.get("title",""),
                finding.get("severity","INFO"),
                finding.get("description",""),
                finding.get("evidence",""),
                finding.get("remediation",""),
                finding.get("cve",""),
                finding.get("url",""),
                "new",
                finding.get("timestamp", datetime.now().isoformat())
            ))
            fid = cur.lastrowid
            c.commit()
        return fid, False  # (id, is_duplicate)

    def get_findings(self, program_id=None, severity=None,
                     status=None, limit=100):
        conditions = ["1=1"]
        params = []
        if program_id:
            conditions.append("program_id=?")
            params.append(program_id)
        if severity:
            conditions.append("severity=?")
            params.append(severity)
        if status:
            conditions.append("status=?")
            params.append(status)

        sql = f"""
        SELECT * FROM findings
        WHERE {' AND '.join(conditions)}
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4
            END,
            found_at DESC
        LIMIT ?
        """
        params.append(limit)
        with self.conn() as c:
            rows = c.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def is_known_duplicate(self, finding: dict, program_id: str) -> bool:
        fp = self.fingerprint(finding)
        with self.conn() as c:
            row = c.execute(
                "SELECT id FROM known_vulns WHERE fingerprint=? AND program_id=?",
                (fp, program_id)
            ).fetchone()
        return row is not None

    def mark_known(self, finding: dict, program_id: str, report_id=None):
        fp = self.fingerprint(finding)
        with self.conn() as c:
            c.execute("""
            INSERT OR IGNORE INTO known_vulns
                (fingerprint, program_id, title, severity, url, first_seen, report_id, status)
            VALUES (?,?,?,?,?,?,?,?)
            """, (fp, program_id, finding.get("title",""),
                  finding.get("severity",""), finding.get("url",""),
                  datetime.now().isoformat(), report_id, "known"))
            c.commit()

    # ── Submissions ───────────────────────────────────────────

    def create_submission(self, finding_id, program_id, platform,
                          title, severity, report_path=None):
        with self.conn() as c:
            cur = c.execute("""
            INSERT INTO submissions
                (finding_id, program_id, platform, title, severity,
                 status, submitted_at, report_path)
            VALUES (?,?,?,?,?,?,?,?)
            """, (finding_id, program_id, platform, title, severity,
                  "submitted", datetime.now().isoformat(), report_path))
            sid = cur.lastrowid
            c.execute(
                "UPDATE findings SET status='submitted', submitted_at=? WHERE id=?",
                (datetime.now().isoformat(), finding_id)
            )
            c.commit()
        return sid

    def update_submission(self, submission_id, status, bounty=0,
                          platform_ref=None, notes=None):
        with self.conn() as c:
            c.execute("""
            UPDATE submissions SET
                status=?, bounty_paid=?,
                platform_ref=COALESCE(?,platform_ref),
                response_notes=COALESCE(?,response_notes),
                resolved_at=CASE WHEN ?='resolved' THEN ? ELSE resolved_at END
            WHERE id=?
            """, (status, bounty, platform_ref, notes,
                  status, datetime.now().isoformat(), submission_id))
            c.commit()

    # ── Earnings ──────────────────────────────────────────────

    def record_earning(self, submission_id=None, program_id=None, platform=None,
                       amount=0, currency="USD", finding_title="", severity=""):
        # Simple USD conversion rates (approximate)
        usd_rates = {"USD":1.0,"EUR":1.08,"GBP":1.27,"CHF":1.12,"JPY":0.0067}
        amount_usd = amount * usd_rates.get(currency, 1.0)

        with self.conn() as c:
            c.execute("""
            INSERT INTO earnings
                (submission_id, program_id, platform, amount, currency,
                 amount_usd, paid_at, finding_title, severity)
            VALUES (?,?,?,?,?,?,?,?,?)
            """, (submission_id, program_id, platform, amount, currency,
                  amount_usd, datetime.now().isoformat(), finding_title, severity))
            c.commit()

    def get_earnings_summary(self):
        with self.conn() as c:
            row = c.execute("""
            SELECT
                COUNT(*) as total_payments,
                SUM(amount_usd) as total_usd,
                AVG(amount_usd) as avg_per_finding,
                MAX(amount_usd) as biggest_bounty,
                MIN(paid_at) as first_payment,
                MAX(paid_at) as last_payment
            FROM earnings
            """).fetchone()

            by_platform = c.execute("""
            SELECT platform, COUNT(*) as count, SUM(amount_usd) as total
            FROM earnings GROUP BY platform ORDER BY total DESC
            """).fetchall()

            by_severity = c.execute("""
            SELECT severity, COUNT(*) as count, SUM(amount_usd) as total
            FROM earnings GROUP BY severity ORDER BY total DESC
            """).fetchall()

        return {
            "summary":     dict(row) if row else {},
            "by_platform": [dict(r) for r in by_platform],
            "by_severity": [dict(r) for r in by_severity],
        }

    # ── Subdomains ────────────────────────────────────────────

    def save_subdomain(self, domain, subdomain, source="unknown",
                       ip=None, status="unknown"):
        with self.conn() as c:
            c.execute("""
            INSERT OR IGNORE INTO subdomains
                (domain, subdomain, ip_address, source, status, discovered_at)
            VALUES (?,?,?,?,?,?)
            """, (domain, subdomain, ip, source, status,
                  datetime.now().isoformat()))
            c.commit()

    def get_subdomains(self, domain, alive_only=False):
        sql = "SELECT * FROM subdomains WHERE domain=?"
        params = [domain]
        if alive_only:
            sql += " AND is_alive=1"
        with self.conn() as c:
            rows = c.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ── Statistics ────────────────────────────────────────────

    def get_dashboard_stats(self):
        with self.conn() as c:
            programs   = c.execute("SELECT COUNT(*) FROM programs WHERE status='active'").fetchone()[0]
            scans      = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            findings   = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            submitted  = c.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]
            earned     = c.execute("SELECT COALESCE(SUM(amount_usd),0) FROM earnings").fetchone()[0]
            critical   = c.execute("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'").fetchone()[0]
            high       = c.execute("SELECT COUNT(*) FROM findings WHERE severity='HIGH'").fetchone()[0]
            new_finds  = c.execute("SELECT COUNT(*) FROM findings WHERE status='new'").fetchone()[0]

        return {
            "programs":   programs,
            "scans":      scans,
            "findings":   findings,
            "submitted":  submitted,
            "earned_usd": round(earned, 2),
            "critical":   critical,
            "high":       high,
            "new":        new_finds,
        }


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    import tempfile
    print("\n=== DATABASE REGRESSION TESTS ===")
    passed = failed = 0
    tmp = tempfile.mktemp(suffix=".db")
    db = Database(tmp)

    tests = [
        ("Tables created",
         lambda: bool(db.get_dashboard_stats())),

        ("Upsert program",
         lambda: (db.upsert_program({
             "id":"h1_test","platform":"hackerone","name":"TestCo",
             "handle":"testco","url":"https://hackerone.com/testco",
             "policy_url":"","status":"active","bounty_min":100,
             "bounty_max":5000,"currency":"USD","response_time":3,
             "allows_auto":1,"vdp_only":0,"raw_json":"{}",
             "fetched_at":datetime.now().isoformat(),"rank_score":85.0
         }) or True)),

        ("Get top programs",
         lambda: isinstance(db.get_top_programs(), list)),

        ("Upsert scope",
         lambda: (db.upsert_scope("h1_test",[
             {"asset_type":"url","target":"*.testco.com","in_scope":1,"eligible_for_bounty":1}
         ]) or True)),

        ("Get scope",
         lambda: len(db.get_scope("h1_test")) == 1),

        ("Create scan",
         lambda: isinstance(db.create_scan("http://testco.com","h1_test"), int)),

        ("Save finding — not duplicate",
         lambda: db.save_finding({
             "title":"SQL Injection","severity":"CRITICAL",
             "url":"http://testco.com/login","module":"sqli",
             "description":"SQLi found","evidence":"payload",
             "remediation":"use params","cve":"CWE-89"
         })[1] == False),

        ("Save same finding — is duplicate",
         lambda: db.save_finding({
             "title":"SQL Injection","severity":"CRITICAL",
             "url":"http://testco.com/login","module":"sqli",
             "description":"SQLi found","evidence":"payload",
             "remediation":"use params","cve":"CWE-89"
         })[1] == True),

        ("Get findings",
         lambda: len(db.get_findings()) >= 1),

        ("Fingerprint is deterministic",
         lambda: db.fingerprint({"title":"X","url":"Y","parameter":"","severity":"HIGH"}) ==
                 db.fingerprint({"title":"X","url":"Y","parameter":"","severity":"HIGH"})),

        ("Record earning",
         lambda: (db.record_earning(1,"h1_test","hackerone",500,"USD","SQLi","CRITICAL") or True)),

        ("Earnings summary",
         lambda: db.get_earnings_summary()["summary"].get("total_payments",0) >= 1),

        ("Save subdomain",
         lambda: (db.save_subdomain("testco.com","api.testco.com","crt.sh") or True)),

        ("Get subdomains",
         lambda: len(db.get_subdomains("testco.com")) >= 1),

        ("Dashboard stats has all keys",
         lambda: all(k in db.get_dashboard_stats() for k in
             ["programs","scans","findings","submitted","earned_usd"])),

        ("Known vuln dedup",
         lambda: (
             db.mark_known({"title":"XSS","url":"http://x.com","severity":"HIGH"},"h1_test") or True,
             db.is_known_duplicate({"title":"XSS","url":"http://x.com","severity":"HIGH","parameter":""},"h1_test")
         )[1]),
    ]

    for name, fn in tests:
        try:
            result = fn()
            if result:
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    try:
        os.unlink(tmp)
    except Exception:
        pass

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed



def _test_dedup(db):
    import time
    key = f"DeupTest_{int(time.time()*1000)}"
    r1 = db.save_finding({"title":key,"severity":"HIGH",
        "url":"http://dedup.test.com","module":"xss",
        "description":"d","evidence":"e","remediation":"r","cve":""})
    r2 = db.save_finding({"title":key,"severity":"HIGH",
        "url":"http://dedup.test.com","module":"xss",
        "description":"d","evidence":"e","remediation":"r","cve":""})
    return r1[1] == False and r2[1] == True

def run_stress_tests():
    import tempfile, threading
    print("\n=== DATABASE STRESS TESTS ===")
    passed = failed = 0
    tmp = tempfile.mktemp(suffix=".db")
    db = Database(tmp)

    # Seed program
    db.upsert_program({
        "id":"stress_prog","platform":"hackerone","name":"StressCo",
        "handle":"stressco","url":"","policy_url":"","status":"active",
        "bounty_min":0,"bounty_max":1000,"currency":"USD","response_time":1,
        "allows_auto":1,"vdp_only":0,"raw_json":"{}",
        "fetched_at":datetime.now().isoformat(),"rank_score":50.0
    })

    # Fresh db for concurrent tests
    import tempfile as _tf
    fresh_tmp = _tf.mktemp(suffix='.db')
    fresh_db  = Database(fresh_tmp)

    tests = [
        ("Bulk findings insert (500)",
         lambda: (
             [db.save_finding({
                 "title":f"Finding {i}","severity":["CRITICAL","HIGH","MEDIUM","LOW","INFO"][i%5],
                 "url":f"http://stress.com/page/{i}","module":"sqli",
                 "description":"test","evidence":"ev","remediation":"rem","cve":""
             }, program_id="stress_prog") for i in range(500)]
             and db.get_dashboard_stats()["findings"] >= 500
         )),

        ("Dedup works at scale",
         lambda: _test_dedup(db)),

        ("Bulk subdomains (200)",
         lambda: (
             [db.save_subdomain("stress.com", f"sub{i}.stress.com") for i in range(200)]
             and len(db.get_subdomains("stress.com")) >= 200
         )),

        ("Concurrent writes thread-safe",
         lambda: _test_concurrent_writes(fresh_db)),

        ("Earnings aggregation",
         lambda: (
             [db.record_earning(1,"stress_prog","hackerone",
              i*100,"USD",f"Find {i}","HIGH") for i in range(1,11)],
             db.get_earnings_summary()["summary"]["total_usd"] >= 5500
         )[1]),

        ("Large scope upsert (100 entries)",
         lambda: (
             db.upsert_scope("stress_prog",
                 [{"asset_type":"url","target":f"*.sub{i}.stress.com",
                   "in_scope":1,"eligible_for_bounty":1} for i in range(100)]) or True,
             len(db.get_scope("stress_prog")) == 100
         )[1]),
    ]

    for name, fn in tests:
        try:
            result = fn()
            if result:
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    try:
        os.unlink(tmp)
    except Exception:
        pass

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


def _test_concurrent_writes(db):
    """Test concurrent writes - each thread uses own connection."""
    import tempfile
    errors = []
    # Use a fresh temp db for concurrent test
    tmp = tempfile.mktemp(suffix="_concurrent.db")
    
    def worker(tid):
        try:
            local_db = Database(tmp)
            for i in range(5):
                local_db.save_finding({
                    "title":f"Conc_{tid}_{i}",
                    "severity":"INFO",
                    "url":f"http://conc{tid}.com/{i}",
                    "module":"test",
                    "description":"d","evidence":"e","remediation":"r","cve":""
                })
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker,args=(t,)) for t in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    try: __import__('os').unlink(tmp)
    except: pass
    return len(errors) == 0


if __name__ == "__main__":
    rp, rf = run_regression_tests()
    sp, sf = run_stress_tests()
    print(f"\nTOTAL: {rp+sp} passed  {rf+sf} failed")
    import sys; sys.exit(0 if rf+sf==0 else 1)
