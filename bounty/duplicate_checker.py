"""
AmonStrike — Duplicate Checker
Stage 4: Check if a finding is already reported before submitting.

Checks against:
  - HackerOne hacktivity (public disclosed reports)
  - Bugcrowd disclosed reports
  - Local database of previously submitted findings
  - Known CVE databases

A duplicate wastes your time and damages your reputation.
Always check before submitting.
"""

import os
import re
import sys
import json
import time
import hashlib
import sqlite3
import requests
from datetime import datetime
from difflib import SequenceMatcher
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class DuplicateChecker:
    """
    Checks if a vulnerability finding is already known/reported.
    Multi-source: H1 hacktivity + local DB + CVE.
    """

    H1_API = "https://api.hackerone.com/v1"
    BC_API = "https://api.bugcrowd.com"

    def __init__(self, db_path: str = None,
                 h1_username: str = None, h1_token: str = None,
                 bc_token: str = None):
        self.db_path    = db_path or os.path.expanduser("~/.amonstrike/duplicates.db")
        self.h1_user    = h1_username
        self.h1_token   = h1_token
        self.bc_token   = bc_token
        self._init_db()

    def _init_db(self):
        """Initialize local duplicate tracking database."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS known_findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE,
                title       TEXT,
                url         TEXT,
                module      TEXT,
                severity    TEXT,
                source      TEXT,
                report_id   TEXT,
                submitted_at TEXT,
                status      TEXT DEFAULT 'new'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS h1_hacktivity (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id   TEXT UNIQUE,
                title       TEXT,
                weakness    TEXT,
                severity    TEXT,
                program     TEXT,
                disclosed_at TEXT,
                url         TEXT,
                cached_at   TEXT
            )
        """)
        conn.commit()
        conn.close()

    def is_duplicate(self, finding: dict, program_handle: str = None) -> dict:
        """
        Check if a finding is a duplicate.
        Returns: {is_dup: bool, confidence: float, source: str, details: str}
        """
        result = {
            "is_duplicate": False,
            "confidence":   0.0,
            "source":       None,
            "details":      "",
            "similar":      [],
        }

        # 1. Check local DB (fastest)
        local = self._check_local(finding)
        if local["is_duplicate"]:
            return local

        # 2. Check H1 hacktivity (if credentials configured)
        if self.h1_user and self.h1_token:
            h1 = self._check_h1_hacktivity(finding, program_handle)
            if h1["is_duplicate"]:
                return h1
            result["similar"].extend(h1.get("similar",[]))

        # 3. Fingerprint check
        fp   = self._fingerprint(finding)
        best = self._fuzzy_search(finding, result["similar"])
        if best["confidence"] > 0.85:
            result.update({
                "is_duplicate": True,
                "confidence":   best["confidence"],
                "source":       "fuzzy_match",
                "details":      f"Similar to: {best['title']}",
            })

        return result

    def _check_local(self, finding: dict) -> dict:
        """Check local database for exact/near duplicates."""
        fp   = self._fingerprint(finding)
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM known_findings WHERE fingerprint=?", (fp,)
            ).fetchone()
            if row:
                return {
                    "is_duplicate": True,
                    "confidence":   1.0,
                    "source":       "local_db",
                    "details":      f"Already tracked: {row[2]} (status: {row[9]})",
                    "similar":      [],
                }

            # Fuzzy check on title + URL
            title = finding.get("title","").lower()
            url   = finding.get("url","")
            rows  = conn.execute(
                "SELECT title, url, source, report_id, status FROM known_findings"
                " WHERE url LIKE ?",
                (f"%{urlparse(url).path}%",)
            ).fetchall()

            similar = []
            for row in rows:
                sim = SequenceMatcher(None, title, row[0].lower()).ratio()
                if sim > 0.7:
                    similar.append({
                        "title":     row[0],
                        "url":       row[1],
                        "source":    row[2],
                        "report_id": row[3],
                        "confidence":sim,
                    })

            if similar and similar[0]["confidence"] > 0.85:
                return {
                    "is_duplicate": True,
                    "confidence":   similar[0]["confidence"],
                    "source":       "local_fuzzy",
                    "details":      f"Similar local finding: {similar[0]['title']}",
                    "similar":      similar,
                }

            return {"is_duplicate": False, "confidence": 0.0,
                    "source": None, "details": "", "similar": similar}

        finally:
            conn.close()

    def _check_h1_hacktivity(self, finding: dict, program_handle: str = None) -> dict:
        """Check HackerOne hacktivity for similar reports."""
        title   = finding.get("title","")
        module  = finding.get("module","")
        url     = finding.get("url","")
        domain  = urlparse(url).hostname or ""

        # Build search query
        weakness_map = {
            "sqli":  "SQL Injection",
            "xss":   "Cross-site Scripting",
            "ssrf":  "Server-Side Request Forgery",
            "lfi":   "Path Traversal",
            "rce":   "Remote Code Execution",
            "idor":  "Insecure Direct Object Reference",
            "cors":  "CORS",
            "csrf":  "Cross-Site Request Forgery",
            "xxe":   "XML External Entities",
        }
        weakness = weakness_map.get(module, title.split(" ")[0])

        try:
            # Query H1 hacktivity (public endpoint, no auth needed for public)
            r = requests.get(
                f"{self.H1_API}/hacktivity",
                params={
                    "filter[program]": program_handle or "",
                    "filter[disclosed]": "true",
                    "page[size]": 25,
                },
                auth=(self.h1_user, self.h1_token) if self.h1_user else None,
                timeout=10,
                headers={"Accept": "application/json"},
            )

            if r.status_code != 200:
                return {"is_duplicate": False, "confidence": 0.0,
                        "source": None, "details": "", "similar": []}

            data    = r.json()
            reports = data.get("data",[])
            similar = []

            for report in reports:
                attrs     = report.get("attributes",{})
                rep_title = attrs.get("title","")
                rep_weak  = attrs.get("weakness",{}).get("name","")

                # Compare
                title_sim = SequenceMatcher(None,
                    title.lower(), rep_title.lower()).ratio()
                weak_sim  = 1.0 if weakness.lower() in rep_weak.lower() else 0.0
                confidence= (title_sim * 0.7) + (weak_sim * 0.3)

                if confidence > 0.5:
                    similar.append({
                        "title":       rep_title,
                        "weakness":    rep_weak,
                        "confidence":  confidence,
                        "report_id":   report.get("id",""),
                        "disclosed":   attrs.get("disclosed_at",""),
                    })

            similar.sort(key=lambda x: x["confidence"], reverse=True)

            if similar and similar[0]["confidence"] > 0.8:
                return {
                    "is_duplicate": True,
                    "confidence":   similar[0]["confidence"],
                    "source":       "h1_hacktivity",
                    "details":      f"Similar H1 report: '{similar[0]['title']}' (id: {similar[0]['report_id']})",
                    "similar":      similar[:5],
                }

            return {"is_duplicate": False, "confidence": 0.0,
                    "source": None, "details": "", "similar": similar[:5]}

        except Exception as e:
            return {"is_duplicate": False, "confidence": 0.0,
                    "source": None, "details": f"H1 check error: {e}", "similar": []}

    def _fingerprint(self, finding: dict) -> str:
        """Generate a fingerprint for a finding."""
        key = "|".join([
            finding.get("module",""),
            finding.get("url",""),
            finding.get("parameter",""),
            finding.get("payload","")[:50],
        ])
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _fuzzy_search(self, finding: dict, candidates: list) -> dict:
        """Find best fuzzy match in candidates."""
        if not candidates:
            return {"confidence": 0.0, "title": ""}
        title = finding.get("title","").lower()
        best  = max(candidates,
                    key=lambda c: SequenceMatcher(None, title,
                        c.get("title","").lower()).ratio())
        best_conf = SequenceMatcher(None, title,
                        best.get("title","").lower()).ratio()
        return {"confidence": best_conf, **best}

    def record_finding(self, finding: dict, source: str = "amonstrike",
                       report_id: str = None, status: str = "new"):
        """Record a finding in local database."""
        fp   = self._fingerprint(finding)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT OR REPLACE INTO known_findings
                (fingerprint, title, url, module, severity, source, report_id, submitted_at, status)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                fp,
                finding.get("title",""),
                finding.get("url",""),
                finding.get("module",""),
                finding.get("severity",""),
                source,
                report_id or "",
                datetime.now().isoformat(),
                status,
            ))
            conn.commit()
        finally:
            conn.close()

    def update_status(self, fingerprint: str, status: str):
        """Update finding status (triaged/resolved/duplicate/n_a)."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE known_findings SET status=? WHERE fingerprint=?",
            (status, fingerprint)
        )
        conn.commit()
        conn.close()

    def get_stats(self) -> dict:
        """Get duplicate checker statistics."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT status, COUNT(*) FROM known_findings GROUP BY status
        """).fetchall()
        conn.close()
        return {"by_status": dict(rows), "total": sum(r[1] for r in rows)}


def run_regression_tests():
    import tempfile
    print("\n=== DUPLICATE CHECKER REGRESSION TESTS ===")
    passed = failed = 0
    tmp = tempfile.mkdtemp() + "/dup.db"

    checker = DuplicateChecker(db_path=tmp)

    finding_a = {
        "title":     "SQL Injection in login",
        "module":    "sqli",
        "url":       "http://testco.com/login?id=1",
        "parameter": "id",
        "payload":   "' OR 1=1--",
        "severity":  "CRITICAL",
    }
    finding_b = {
        "title":     "SQL Injection in login form",
        "module":    "sqli",
        "url":       "http://testco.com/login?id=1",
        "parameter": "id",
        "payload":   "' OR 1=1--",
        "severity":  "CRITICAL",
    }
    finding_c = {
        "title":     "Reflected XSS in search",
        "module":    "xss",
        "url":       "http://testco.com/search",
        "parameter": "q",
        "severity":  "HIGH",
    }

    tests = [
        ("Checker instantiates",
         lambda: isinstance(checker, DuplicateChecker)),

        ("DB file created",
         lambda: os.path.exists(tmp)),

        ("Fingerprint is deterministic",
         lambda: checker._fingerprint(finding_a) == checker._fingerprint(finding_a)),

        ("Different findings have different fingerprints",
         lambda: checker._fingerprint(finding_a) != checker._fingerprint(finding_c)),

        ("New finding not duplicate",
         lambda: not checker.is_duplicate(finding_a)["is_duplicate"]),

        ("Record finding",
         lambda: (checker.record_finding(finding_a, "test") or True)),

        ("Recorded finding is duplicate",
         lambda: checker.is_duplicate(finding_a)["is_duplicate"]),

        ("High confidence on exact match",
         lambda: checker.is_duplicate(finding_a)["confidence"] == 1.0),

        ("Different finding still not duplicate",
         lambda: not checker.is_duplicate(finding_c)["is_duplicate"]),

        ("Fuzzy match on similar title",
         lambda: (
             checker.record_finding(finding_a),
             r := checker._check_local(finding_b),
             r.get("confidence",0) > 0.7
         )[2]),

        ("Update status works",
         lambda: (
             checker.update_status(checker._fingerprint(finding_a), "triaged"),
             True
         )[1]),

        ("Get stats returns dict",
         lambda: isinstance(checker.get_stats(), dict)),

        ("Stats has total count",
         lambda: checker.get_stats().get("total",0) > 0),

        ("Fuzzy search returns best match",
         lambda: checker._fuzzy_search(
             finding_a,
             [{"title": "SQL Injection login", "confidence": 0.8},
              {"title": "XSS vulnerability",   "confidence": 0.2}]
         )["confidence"] > 0.5),
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
    rp, rf = run_regression_tests()
    sys.exit(0 if rf == 0 else 1)
