"""
AmonStrike — Evidence Collector
Captures full proof of every finding for bug bounty submissions.

For every finding:
  - Full HTTP request (headers + body)
  - Full HTTP response (headers + body)
  - Request timestamp
  - Server headers
  - Screenshot (if headless browser available)
  - Formatted PoC steps
  - CVSS score

This is what separates a winning report from a rejected one.
Professional evidence wins bounties.
"""

import os
import json
import time
import hashlib
import requests
from datetime import datetime
from urllib.parse import urlparse, urlencode


class EvidenceCollector:
    """
    Collects and formats complete evidence for vulnerability findings.
    Produces submission-ready evidence packages.
    """

    def __init__(self, output_dir: str, target_url: str):
        self.output_dir = output_dir
        self.target_url = target_url
        self.session    = requests.Session()
        self.session.headers.update({
            "User-Agent": "AmonStrike/2.0 Security Research"
        })
        os.makedirs(output_dir, exist_ok=True)

    def collect(self, finding: dict, request_obj=None, response_obj=None) -> dict:
        """
        Collect complete evidence for a finding.
        Returns enriched finding with full evidence.
        """
        evidence = {
            "finding_id":   self._fingerprint(finding),
            "collected_at": datetime.now().isoformat(),
            "target":       self.target_url,
            "title":        finding.get("title",""),
            "severity":     finding.get("severity",""),
            "module":       finding.get("module",""),
        }

        # Capture HTTP evidence
        if request_obj and response_obj:
            evidence["http"] = self._capture_http(request_obj, response_obj)
        elif finding.get("url"):
            evidence["http"] = self._reproduce_request(finding)

        # Format PoC steps
        evidence["poc_steps"] = self._format_poc_steps(finding)

        # CVSS score
        from verify.cvss_calculator import CVSSCalculator
        calc   = CVSSCalculator()
        cvss_r = calc.score_finding(finding)
        evidence["cvss"] = cvss_r

        # Save evidence to file
        evidence_path = self._save_evidence(finding, evidence)
        evidence["evidence_file"] = evidence_path

        # Enrich finding with evidence
        enriched = dict(finding)
        enriched["cvss_score"]   = cvss_r["score"]
        enriched["cvss_vector"]  = cvss_r["vector"]
        enriched["evidence_file"] = evidence_path
        enriched["evidence"]     = self._format_evidence_text(evidence)

        return enriched

    def _capture_http(self, request_obj, response_obj) -> dict:
        """Format full HTTP request and response."""
        # Format request
        req = request_obj
        req_text = f"{req.method} {req.url} HTTP/1.1\n"
        for k, v in req.headers.items():
            req_text += f"{k}: {v}\n"
        if req.body:
            req_text += f"\n{req.body}"

        # Format response
        resp = response_obj
        resp_text = f"HTTP {resp.status_code} {resp.reason}\n"
        for k, v in resp.headers.items():
            resp_text += f"{k}: {v}\n"
        resp_text += f"\n{resp.text[:2000]}"

        return {
            "request":  req_text,
            "response": resp_text,
            "status_code": resp.status_code,
            "response_time": getattr(resp, "elapsed", None) and
                            resp.elapsed.total_seconds(),
        }

    def _reproduce_request(self, finding: dict) -> dict:
        """Reproduce the request to capture live evidence."""
        url     = finding.get("url", self.target_url)
        payload = finding.get("payload","")
        param   = finding.get("parameter","")

        try:
            if payload and param:
                resp = self.session.get(
                    url, params={param: payload}, timeout=10,
                    allow_redirects=False
                )
            else:
                resp = self.session.get(url, timeout=10, allow_redirects=False)

            # Format request
            req_text = f"GET {resp.url} HTTP/1.1\n"
            for k, v in resp.request.headers.items():
                req_text += f"{k}: {v}\n"

            # Format response
            resp_text = f"HTTP {resp.status_code} {resp.reason}\n"
            for k, v in resp.headers.items():
                resp_text += f"{k}: {v}\n"
            resp_text += f"\n{resp.text[:2000]}"

            return {
                "request":       req_text,
                "response":      resp_text,
                "status_code":   resp.status_code,
                "response_time": resp.elapsed.total_seconds(),
            }
        except Exception as e:
            return {"error": str(e), "request": "", "response": ""}

    def _format_poc_steps(self, finding: dict) -> list:
        """Generate step-by-step reproduction steps."""
        title   = finding.get("title","")
        url     = finding.get("url","")
        payload = finding.get("payload","")
        param   = finding.get("parameter","")
        module  = finding.get("module","")
        sev     = finding.get("severity","")

        steps = [
            f"1. Navigate to: {url}",
        ]

        # Module-specific steps
        poc_templates = {
            "sqli": [
                f"2. Identify parameter: {param or 'id'}",
                "3. Inject payload: " + str(payload or "' OR 1=1--"),
                "4. Observe database error or different response",
                "5. Confirm with boolean-based payload: ' AND 1=1-- vs ' AND 1=2--",
            ],
            "xss": [
                f"2. Find input field or parameter: {param or 'search'}",
                f"3. Submit XSS payload: {payload or '<script>alert(document.domain)</script>'}",
                "4. Observe JavaScript execution in browser",
                "5. Check browser console for alert or network request to attacker domain",
            ],
            "ssrf": [
                "2. Find URL parameter or file upload that makes HTTP requests",
                f"3. Submit payload: {payload or 'http://169.254.169.254/latest/meta-data/'}",
                "4. Observe response contains AWS metadata or internal service response",
            ],
            "idor": [
                f"2. Authenticate as User A, note resource ID: {param or 'id=1'}",
                "3. Authenticate as User B",
                "4. Change resource ID to User A's ID",
                "5. Observe successful access to User A's data",
            ],
            "lfi": [
                f"2. Identify file parameter: {param or 'file'}",
                f"3. Submit traversal payload: {payload or '../../../../etc/passwd'}",
                "4. Observe /etc/passwd content in response",
            ],
            "cors": [
                f"2. Send request to {url} with: Origin: https://evil.com",
                "3. Observe: Access-Control-Allow-Origin: https://evil.com",
                "4. Confirm with: Access-Control-Allow-Credentials: true",
                "5. Craft exploit page to steal cookies cross-origin",
            ],
        }

        module_steps = poc_templates.get(module, [
            f"2. Submit the following payload to the vulnerable parameter:",
            f"   {payload or 'See evidence below'}",
            "3. Observe the vulnerability in the response",
        ])

        steps.extend(module_steps)
        steps.append(f"\nExpected result: {finding.get('description','')[:200]}")

        return steps

    def _format_evidence_text(self, evidence: dict) -> str:
        """Format evidence as text for report embedding."""
        lines = []
        lines.append(f"=== EVIDENCE PACKAGE ===")
        lines.append(f"Collected: {evidence.get('collected_at','')}")
        lines.append(f"Target: {evidence.get('target','')}")
        lines.append("")

        cvss = evidence.get("cvss",{})
        if cvss:
            lines.append(f"CVSS Score: {cvss.get('score',0)} ({cvss.get('severity','')})")
            lines.append(f"Vector: {cvss.get('vector','')}")
            lines.append("")

        poc = evidence.get("poc_steps",[])
        if poc:
            lines.append("=== PROOF OF CONCEPT ===")
            lines.extend(poc)
            lines.append("")

        http = evidence.get("http",{})
        if http.get("request"):
            lines.append("=== HTTP REQUEST ===")
            lines.append(http["request"][:1000])
            lines.append("")
            lines.append("=== HTTP RESPONSE ===")
            lines.append(http.get("response","")[:1000])

        return "\n".join(lines)

    def _save_evidence(self, finding: dict, evidence: dict) -> str:
        """Save evidence package to JSON file."""
        fp   = self._fingerprint(finding)
        path = os.path.join(self.output_dir, f"evidence_{fp}.json")
        with open(path, "w") as f:
            json.dump(evidence, f, indent=2, default=str)
        return path

    def _fingerprint(self, finding: dict) -> str:
        key = "|".join([
            finding.get("title",""),
            finding.get("url",""),
            finding.get("module",""),
        ])
        return hashlib.sha256(key.encode()).hexdigest()[:12]

    def collect_all(self, findings: list) -> list:
        """Collect evidence for all findings."""
        enriched = []
        for finding in findings:
            try:
                enriched.append(self.collect(finding))
            except Exception as e:
                finding["evidence_error"] = str(e)
                enriched.append(finding)
        return enriched


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    import tempfile
    print("\n=== EVIDENCE COLLECTOR REGRESSION TESTS ===")
    passed = failed = 0

    tmp = tempfile.mkdtemp()
    ec  = EvidenceCollector(tmp, "http://test.com")

    sample_finding = {
        "title":       "SQL Injection",
        "severity":    "CRITICAL",
        "module":      "sqli",
        "url":         "http://test.com/login?id=1",
        "parameter":   "id",
        "payload":     "' OR 1=1--",
        "description": "SQL injection allows authentication bypass",
        "evidence":    "Error: You have an error in your SQL syntax",
        "remediation": "Use parameterized queries",
        "cve":         "CWE-89",
    }

    tests = [
        ("Collector instantiates",
         lambda: isinstance(ec, EvidenceCollector)),

        ("Fingerprint generated",
         lambda: len(ec._fingerprint(sample_finding)) == 12),

        ("Fingerprint deterministic",
         lambda: ec._fingerprint(sample_finding) == ec._fingerprint(sample_finding)),

        ("PoC steps generated",
         lambda: len(ec._format_poc_steps(sample_finding)) >= 3),

        ("PoC contains URL",
         lambda: "http://test.com" in "\n".join(ec._format_poc_steps(sample_finding))),

        ("SQLi PoC specific steps",
         lambda: any("payload" in s.lower() or "inject" in s.lower()
                    for s in ec._format_poc_steps({"module":"sqli","url":"http://x.com"}))),

        ("XSS PoC specific steps",
         lambda: any("alert" in s.lower() or "xss" in s.lower() or "script" in s.lower()
                    for s in ec._format_poc_steps({"module":"xss","url":"http://x.com"}))),

        ("Evidence text formatted",
         lambda: "EVIDENCE PACKAGE" in ec._format_evidence_text({
             "collected_at": "2026-01-01",
             "target": "http://test.com",
             "cvss": {"score":9.8,"severity":"Critical","vector":"CVSS:3.1/AV:N"},
             "poc_steps": ["1. Navigate to http://test.com"],
             "http": {"request":"GET / HTTP/1.1","response":"HTTP 200 OK"},
         })),

        ("CVSS score in evidence",
         lambda: "CVSS" in ec._format_evidence_text({
             "collected_at":"","target":"","cvss":{"score":9.8,"severity":"Critical","vector":"X"},
             "poc_steps":[],"http":{}
         })),

        ("Evidence file saved",
         lambda: (
             e := ec.collect(sample_finding),
             os.path.exists(e.get("evidence_file",""))
         )[1]),

        ("Enriched finding has CVSS score",
         lambda: ec.collect(sample_finding).get("cvss_score",0) > 0),

        ("Collect all enriches list",
         lambda: len(ec.collect_all([sample_finding])) == 1),

        ("Output dir created",
         lambda: os.path.isdir(tmp)),
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
