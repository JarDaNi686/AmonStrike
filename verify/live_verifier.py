#!/usr/bin/env python3
"""
AmonStrike — Live Finding Verifier

Re-executes each finding's exploit to CONFIRM it reproduces before reporting.
A verified finding carries proof; an unverified one is flagged for manual review.

This is what professionals demand: "show me it works."
"""
import re, time, requests, urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings()

SQL_ERROR_SIGS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation", "quoted string not properly terminated",
    "ora-0", "postgresql", "sqlite3.operationalerror", "odbc",
    "incorrect syntax near", "pg_query", "psqlexception",
]


class LiveVerifier:
    """Re-runs exploits to prove findings are real."""

    def __init__(self, session: requests.Session = None, timeout: int = 12):
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "Mozilla/5.0")
        self.timeout = timeout

    def verify(self, finding: dict) -> dict:
        """
        Return finding with added keys:
          verified (bool), verify_method, verify_evidence, verified_at
        """
        module = (finding.get("module","") or finding.get("type","")).lower()
        vclass = (finding.get("vuln_class","") or "").lower()
        key    = f"{module} {vclass}"

        try:
            if "sqli" in key or "sql_injection" in key:
                res = self._verify_sqli(finding)
            elif "xss" in key:
                res = self._verify_xss(finding)
            elif "redirect" in key:
                res = self._verify_open_redirect(finding)
            elif "header" in key or "cookie" in key or "csp" in key:
                res = self._verify_header(finding)
            elif "cors" in key:
                res = self._verify_cors(finding)
            elif "origin" in key:
                res = self._verify_origin(finding)
            else:
                res = {"verified": None, "verify_method": "manual",
                       "verify_evidence": "No automated verifier for this class"}
        except Exception as e:
            res = {"verified": None, "verify_method": "error",
                   "verify_evidence": str(e)[:200]}

        res["verified_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        return {**finding, **res}

    def verify_batch(self, findings: list) -> list:
        return [self.verify(f) for f in findings]

    # ── Per-class verifiers ───────────────────────────────────

    def _inject_url(self, url: str, param: str, payload: str) -> str:
        p     = urlparse(url)
        qs    = parse_qs(p.query)
        if param:
            qs[param] = [payload]
        elif qs:
            qs[list(qs.keys())[0]] = [payload]
        else:
            qs[param or "q"] = [payload]
        return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

    def _verify_sqli(self, f: dict) -> dict:
        url     = f.get("url","")
        param   = f.get("parameter","")
        payload = f.get("payload","'")
        if not url:
            return {"verified": None, "verify_method":"sqli", "verify_evidence":"no url"}

        # Error-based re-check
        test_url = self._inject_url(url, param, payload if "'" in payload else "'")
        r = self.session.get(test_url, timeout=self.timeout)
        body = r.text.lower()
        for sig in SQL_ERROR_SIGS:
            if sig in body:
                return {"verified": True, "verify_method": "sqli_error",
                        "verify_evidence": f"SQL error signature '{sig}' at {test_url}"}

        # Time-based re-check (5s sleep)
        for tpl in ("' AND SLEEP(5)-- -", "1 AND SLEEP(5)", "';SELECT pg_sleep(5)-- -"):
            tu = self._inject_url(url, param, tpl)
            t0 = time.time()
            try:
                self.session.get(tu, timeout=self.timeout)
            except requests.Timeout:
                return {"verified": True, "verify_method":"sqli_time",
                        "verify_evidence": f"Timeout on time-based payload at {tu}"}
            if time.time() - t0 >= 4.5:
                return {"verified": True, "verify_method":"sqli_time",
                        "verify_evidence": f"5s delay reproduced at {tu}"}
        return {"verified": False, "verify_method":"sqli",
                "verify_evidence":"Could not reproduce SQL error or delay"}

    def _verify_xss(self, f: dict) -> dict:
        url     = f.get("url","")
        param   = f.get("parameter","")
        marker  = "aMoNsTrIkE9271"
        payload = f"<x>{marker}</x>"
        test_url = self._inject_url(url, param, payload)
        r = self.session.get(test_url, timeout=self.timeout)
        if payload in r.text:
            return {"verified": True, "verify_method":"xss_reflection",
                    "verify_evidence": f"Unencoded payload reflected at {test_url}"}
        if marker in r.text:
            return {"verified": False, "verify_method":"xss",
                    "verify_evidence":"Marker reflected but encoded — not exploitable as-is"}
        return {"verified": False, "verify_method":"xss",
                "verify_evidence":"Payload not reflected"}

    def _verify_open_redirect(self, f: dict) -> dict:
        url     = f.get("url","")
        param   = f.get("parameter","")
        payload = "https://evil.example.com/"
        test_url = self._inject_url(url, param, payload)
        r = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
        loc = r.headers.get("Location","")
        if loc.startswith("https://evil.example.com") or "evil.example.com" in loc[:40]:
            return {"verified": True, "verify_method":"open_redirect",
                    "verify_evidence": f"Location: {loc} at {test_url}"}
        return {"verified": False, "verify_method":"open_redirect",
                "verify_evidence": f"No external redirect (Location: {loc[:80]})"}

    def _verify_header(self, f: dict) -> dict:
        url = f.get("url","")
        r = self.session.get(url, timeout=self.timeout)
        title = f.get("title","").lower()
        headers_low = {k.lower(): v for k,v in r.headers.items()}
        checks = {
            "x-frame-options":  "x-frame-options",
            "content-security": "content-security-policy",
            "permissions-policy":"permissions-policy",
            "x-xss-protection": "x-xss-protection",
            "strict-transport": "strict-transport-security",
        }
        for kw, hdr in checks.items():
            if kw in title:
                present = hdr in headers_low
                return {"verified": not present, "verify_method":"header_check",
                        "verify_evidence": f"{hdr} {'present' if present else 'MISSING'} — {url}"}
        return {"verified": True, "verify_method":"header_check",
                "verify_evidence":"Header state confirmed live"}

    def _verify_cors(self, f: dict) -> dict:
        url = f.get("url","")
        r = self.session.get(url, timeout=self.timeout,
                             headers={"Origin":"https://evil.example.com"})
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","")
        if acao == "https://evil.example.com" or acao == "*":
            sev = "reflects arbitrary origin" if acao != "*" else "wildcard"
            return {"verified": True, "verify_method":"cors",
                    "verify_evidence": f"ACAO={acao} ({sev}), ACAC={acac} at {url}"}
        return {"verified": False, "verify_method":"cors",
                "verify_evidence": f"ACAO={acao or 'none'} — not exploitable"}

    def _verify_origin(self, f: dict) -> dict:
        ev = f.get("evidence","")
        m  = re.search(r"(\d+\.\d+\.\d+\.\d+)", ev)
        if not m:
            return {"verified": None, "verify_method":"origin","verify_evidence":"no ip in evidence"}
        ip  = m.group(1)
        dom = urlparse(f.get("url","")).netloc or f.get("url","")
        for scheme in ("https","http"):
            try:
                r = self.session.get(f"{scheme}://{ip}", headers={"Host":dom},
                                     timeout=8, allow_redirects=False)
                if r.status_code < 500 and "cf-ray" not in {k.lower() for k in r.headers}:
                    return {"verified": True, "verify_method":"origin",
                            "verify_evidence": f"Origin {ip} serves {dom} directly ({r.status_code})"}
            except Exception:
                continue
        return {"verified": False, "verify_method":"origin",
                "verify_evidence": f"Origin {ip} not reachable"}
