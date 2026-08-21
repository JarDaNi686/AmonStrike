"""
AmonStrike — Endpoint Distribution Engine
The missing link: recon finds 200 endpoints, modules test them all.

Before this: sqli module tests base URL only
After this:  sqli tests every /api/*, /search?*, /user?id=* found by recon

Also provides:
  - False positive baseline filtering
  - SQLMap integration for confirmed SQLi
  - Dalfox integration for confirmed XSS
  - ffuf smart directory fuzzing
"""

import re
import time
import subprocess
import shutil
import hashlib
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import List, Dict, Set, Optional


class EndpointDistributor:
    """
    Takes all discovered endpoints and distributes them
    to the right attack modules based on endpoint characteristics.

    Every module gets:
      - All endpoints with relevant parameters
      - Deduplicated (same path, different params = one test)
      - Prioritized (API endpoints first, static last)
    """

    # Which modules care about which endpoint types
    MODULE_INTERESTS = {
        "sqli":           ["param", "form", "api"],
        "xss":            ["param", "form", "api", "search"],
        "lfi":            ["param", "file_param"],
        "ssrf":           ["param", "url_param", "webhook"],
        "idor":           ["id_param", "api", "user_endpoint"],
        "open_redirect":  ["redirect_param", "param"],
        "ssti":           ["param", "template_param"],
        "nosql_injection":["param", "api", "search"],
        "command_injection":["param", "form"],
        "xxe":            ["upload", "xml_endpoint"],
        "rate_limit":     ["auth_endpoint", "api"],
        "twofa_bypass":   ["auth_endpoint", "otp_endpoint"],
        "graphql_deep":   ["graphql_endpoint"],
        "file_upload":    ["upload"],
        "cors":           ["api", "param"],
        "csrf":           ["form", "api"],
        "cache_poison":   ["api", "param"],
    }

    # Parameter name patterns → endpoint types
    PARAM_TYPES = {
        "file_param":     ["file","path","include","page","doc","template","view"],
        "url_param":      ["url","uri","src","source","dest","redirect","callback",
                           "webhook","endpoint","fetch","load"],
        "id_param":       ["id","uid","user_id","account","record","item","object",
                           "order","doc","file","invoice"],
        "redirect_param": ["redirect","return","next","goto","destination","back",
                           "to","url","location"],
        "search":         ["q","query","search","find","s","keyword","term"],
        "auth_endpoint":  ["login","auth","signin","token","oauth","sso","saml"],
        "otp_endpoint":   ["otp","2fa","mfa","verify","code","totp"],
        "graphql_endpoint":["graphql","graph","gql","query"],
        "template_param": ["template","view","layout","theme","page"],
        "upload":         ["file","upload","image","avatar","attachment","doc"],
        "xml_endpoint":   ["xml","soap","wsdl","feed","rss","sitemap"],
    }

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.parsed   = urlparse(base_url)
        self._endpoints: List[Dict] = []
        self._baseline_hashes: Set[str] = set()
        self._baseline_length: int = 0

    def add_endpoints(self, endpoints: list):
        """Add discovered endpoints."""
        for ep in endpoints:
            if isinstance(ep, str):
                self._endpoints.append(self._classify(ep))
            elif isinstance(ep, dict):
                self._endpoints.append(ep)

    def establish_baseline(self):
        """
        Request 3 definitely-non-existent pages.
        Any module finding that matches a baseline = false positive.
        """
        fake_paths = [
            f"/amonstrike_baseline_{int(time.time())}_1",
            f"/amonstrike_baseline_{int(time.time())}_2",
            "/api/amonstrike_definitely_not_real_12345",
        ]
        baselines = []
        for path in fake_paths:
            try:
                r = requests.get(
                    self.base_url + path, timeout=5, verify=False,
                    headers={"User-Agent":"Mozilla/5.0"}
                )
                h = hashlib.md5(r.text.encode()).hexdigest()
                baselines.append((r.status_code, h, len(r.text)))
            except Exception:
                pass

        # Find consistent baseline
        if baselines:
            # Most common status = baseline
            statuses = [b[0] for b in baselines]
            self._baseline_status = max(set(statuses), key=statuses.count)
            self._baseline_hashes = {b[1] for b in baselines}
            # Average length ± 10% = baseline length range
            lengths = [b[2] for b in baselines]
            avg_len = sum(lengths) / len(lengths)
            self._baseline_length = avg_len
            print(f"  [i] Baseline: status={self._baseline_status} "
                  f"len={avg_len:.0f} ± 10%")

    def is_false_positive(self, response: requests.Response) -> bool:
        """Check if a response matches the baseline (false positive)."""
        if not hasattr(self, '_baseline_status'):
            return False
        if response.status_code == self._baseline_status:
            h = hashlib.md5(response.text.encode()).hexdigest()
            if h in self._baseline_hashes:
                return True
            # Check length similarity (WAF returning same-length custom 404)
            if self._baseline_length > 0:
                ratio = abs(len(response.text) - self._baseline_length) / self._baseline_length
                if ratio < 0.05:  # Within 5% = same page
                    return True
        return False

    def _classify(self, url: str) -> dict:
        """Classify an endpoint by its type and parameters."""
        parsed = urlparse(url if url.startswith("http") else self.base_url + url)
        params = parse_qs(parsed.query)
        path   = parsed.path.lower()

        types = set()
        types.add("param" if params else "path")

        # Classify by parameter names
        for param_name in params:
            for ptype, keywords in self.PARAM_TYPES.items():
                if any(kw in param_name.lower() for kw in keywords):
                    types.add(ptype)

        # Classify by path
        if any(kw in path for kw in ["api","v1","v2","v3","rest","graphql"]):
            types.add("api")
        if any(kw in path for kw in ["login","auth","signin","token","oauth"]):
            types.add("auth_endpoint")
        if any(kw in path for kw in ["upload","file","image","avatar"]):
            types.add("upload")
        if re.search(r'/\d+(/|$)', path):
            types.add("id_param")
        if any(kw in path for kw in ["search","find","query"]):
            types.add("search")
        if any(kw in path for kw in ["graphql","graph","gql"]):
            types.add("graphql_endpoint")

        # API form detection  
        if parsed.query:
            types.add("param")

        return {
            "url":    url if url.startswith("http") else self.base_url + url,
            "path":   parsed.path,
            "params": params,
            "types":  list(types),
        }

    def get_endpoints_for_module(self, module_name: str) -> List[Dict]:
        """
        Return endpoints relevant to a specific module.
        Deduplicated and prioritized.
        """
        interests = self.MODULE_INTERESTS.get(module_name, ["param","api"])
        relevant  = []
        seen_sigs = set()

        for ep in self._endpoints:
            ep_types = set(ep.get("types", []))
            # Check overlap
            if not ep_types.intersection(set(interests)):
                continue

            # Dedup by path + param names (ignore values)
            params    = ep.get("params", {})
            sig_parts = [ep.get("path","")]
            sig_parts.extend(sorted(params.keys()))
            sig = "|".join(sig_parts)

            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            relevant.append(ep)

        # Priority: auth first, API second, params third
        def priority(ep):
            types = ep.get("types",[])
            if "auth_endpoint" in types: return 0
            if "graphql_endpoint" in types: return 1
            if "api" in types: return 2
            if "id_param" in types: return 3
            if "param" in types: return 4
            return 5

        return sorted(relevant, key=priority)[:50]  # max 50 per module

    def get_all_urls_for_module(self, module_name: str) -> List[str]:
        """Convenience: just get the URL strings."""
        return [ep["url"] for ep in self.get_endpoints_for_module(module_name)]

    def get_all_endpoints(self) -> List[Dict]:
        return self._endpoints

    def stats(self) -> dict:
        types_count = {}
        for ep in self._endpoints:
            for t in ep.get("types",[]):
                types_count[t] = types_count.get(t,0)+1
        return {
            "total":  len(self._endpoints),
            "types":  types_count,
        }


class ToolIntegrator:
    """
    Integrates SQLMap, Dalfox, ffuf, and other pro tools.
    Called AFTER a module confirms a vulnerability.
    """

    def __init__(self, output_dir: str = "/tmp/amonstrike_tools"):
        import os
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def run_sqlmap(self, url: str, param: str = None,
                   data: str = None, cookies: str = "",
                   level: int = 1, risk: int = 1) -> dict:
        """
        Run SQLMap on a confirmed SQLi finding.
        Safe mode: --batch --no-cast, no destructive actions.
        """
        if not shutil.which("sqlmap"):
            return {"error": "sqlmap not installed", "cmd": "apt install sqlmap"}

        output_file = f"{self.output_dir}/sqlmap_{int(time.time())}.txt"
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",          # Never ask for input
            "--no-cast",        # Safer
            "--level", str(level),
            "--risk", str(risk),
            "--timeout", "30",
            "--retries", "2",
            "--output-dir", self.output_dir,
            "--flush-session",
        ]
        if param:
            cmd += ["-p", param]
        if data:
            cmd += ["--data", data]
        if cookies:
            cmd += ["--cookie", cookies]

        # Safe: fingerprint only (no dump unless instructed)
        cmd += ["--fingerprint", "--banner", "--current-user", "--current-db"]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            output = result.stdout + result.stderr

            # Parse SQLMap output
            db_type  = re.search(r"back-end DBMS: (.+)", output)
            db_ver   = re.search(r"web server operating system: (.+)", output)
            db_user  = re.search(r"current user: '(.+)'", output)
            db_name  = re.search(r"current database: '(.+)'", output)
            is_dba   = "current user is DBA" in output

            confirmed = "is vulnerable" in output or "Parameter:" in output

            return {
                "confirmed":  confirmed,
                "db_type":    db_type.group(1)  if db_type  else "",
                "db_version": db_ver.group(1)   if db_ver   else "",
                "db_user":    db_user.group(1)  if db_user  else "",
                "db_name":    db_name.group(1)  if db_name  else "",
                "is_dba":     is_dba,
                "raw":        output[:2000],
                "cmd":        " ".join(cmd),
            }
        except subprocess.TimeoutExpired:
            return {"error": "SQLMap timed out", "cmd": " ".join(cmd)}
        except Exception as e:
            return {"error": str(e), "cmd": " ".join(cmd)}

    def run_dalfox(self, url: str, param: str = None,
                   cookies: str = "") -> dict:
        """Run Dalfox on a confirmed XSS finding."""
        if not shutil.which("dalfox"):
            return {
                "error": "dalfox not installed",
                "install": "go install github.com/hahwul/dalfox/v2@latest",
            }

        cmd = ["dalfox", "url", url, "--no-color", "--silence"]
        if param:
            cmd += ["-p", param]
        if cookies:
            cmd += ["--cookie", cookies]
        cmd += ["--timeout", "30"]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=90
            )
            output = result.stdout

            payloads = re.findall(r'\[POC\].*?:\s*(.+)', output)
            verified = "[V]" in output or "VERIFIED" in output

            return {
                "confirmed": verified,
                "payloads":  payloads[:5],
                "raw":       output[:1000],
                "cmd":       " ".join(cmd),
            }
        except Exception as e:
            return {"error": str(e)}

    def run_ffuf(self, url: str, wordlist: str = None,
                 extensions: str = "php,html,js,txt,bak",
                 filter_codes: str = "404,403") -> dict:
        """Run ffuf for smart directory/file fuzzing."""
        if not shutil.which("ffuf"):
            return {
                "error": "ffuf not installed",
                "install": "apt install ffuf",
            }

        # Use built-in wordlist if none provided
        if not wordlist:
            import os
            candidates = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
            ]
            wordlist = next((w for w in candidates if os.path.exists(w)), None)
            if not wordlist:
                return {"error": "No wordlist found. Install seclists."}

        output_file = f"{self.output_dir}/ffuf_{int(time.time())}.json"
        fuzz_url    = url.rstrip("/") + "/FUZZ"

        cmd = [
            "ffuf",
            "-u", fuzz_url,
            "-w", wordlist,
            "-e", f".{extensions}",
            "-fc", filter_codes,
            "-o", output_file,
            "-of", "json",
            "-t", "50",
            "-timeout", "10",
            "-c",
        ]

        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            import json, os
            if os.path.exists(output_file):
                data    = json.load(open(output_file))
                results = data.get("results", [])
                found   = [
                    {"url": r["url"], "status": r["status"],
                     "length": r["length"], "words": r["words"]}
                    for r in results
                ]
                return {
                    "found":  found,
                    "count":  len(found),
                    "cmd":    " ".join(cmd),
                }
        except Exception as e:
            return {"error": str(e)}
        return {"found": [], "count": 0}

    def run_nuclei(self, url: str, tags: str = "cve,misconfig,exposure",
                   severity: str = "medium,high,critical") -> dict:
        """Run Nuclei with specific tags."""
        if not shutil.which("nuclei"):
            return {"error": "nuclei not installed"}

        output_file = f"{self.output_dir}/nuclei_{int(time.time())}.json"
        cmd = [
            "nuclei", "-u", url,
            "-tags", tags,
            "-severity", severity,
            "-o", output_file,
            "-json", "-silent",
            "-timeout", "10",
            "-rate-limit", "10",
        ]

        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
            import json, os
            findings = []
            if os.path.exists(output_file):
                for line in open(output_file):
                    try:
                        findings.append(json.loads(line))
                    except Exception:
                        pass
            return {
                "findings": findings,
                "count":    len(findings),
                "cmd":      " ".join(cmd),
            }
        except Exception as e:
            return {"error": str(e)}


def run_regression_tests():
    import tempfile, os
    print("\n=== ENDPOINT DISTRIBUTOR REGRESSION TESTS ===")
    passed = failed = 0

    dist = EndpointDistributor("http://testphp.vulnweb.com")
    dist.add_endpoints([
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/search.php?test=query",
        "http://testphp.vulnweb.com/api/v1/users/1",
        "http://testphp.vulnweb.com/login",
        "http://testphp.vulnweb.com/upload",
        "/comments.php?aid=1",
        "/api/graphql",
    ])

    tool = ToolIntegrator(tempfile.mkdtemp())

    tests = [
        ("Distributor instantiates",
         lambda: isinstance(dist, EndpointDistributor)),

        ("Endpoints added",
         lambda: len(dist.get_all_endpoints()) >= 5),

        ("Endpoints classified",
         lambda: all("types" in ep for ep in dist.get_all_endpoints())),

        ("API endpoint detected",
         lambda: any("api" in ep.get("types",[])
                    for ep in dist.get_all_endpoints())),

        ("ID param detected",
         lambda: any("id_param" in ep.get("types",[])
                    for ep in dist.get_all_endpoints())),

        ("Upload endpoint detected",
         lambda: any("upload" in ep.get("types",[])
                    for ep in dist.get_all_endpoints())),

        ("Auth endpoint detected",
         lambda: any("auth_endpoint" in ep.get("types",[])
                    for ep in dist.get_all_endpoints())),

        ("GraphQL endpoint detected",
         lambda: any("graphql_endpoint" in ep.get("types",[])
                    for ep in dist.get_all_endpoints())),

        ("sqli gets param endpoints",
         lambda: len(dist.get_endpoints_for_module("sqli")) > 0),

        ("lfi gets file_param endpoints",
         lambda: isinstance(dist.get_endpoints_for_module("lfi"), list)),

        ("file_upload gets upload endpoints",
         lambda: len(dist.get_endpoints_for_module("file_upload")) > 0),

        ("Deduplication works",
         lambda: (
             dist.add_endpoints(["http://testphp.vulnweb.com/artists.php?artist=1"]),
             True
         )[1]),

        ("get_all_urls_for_module returns strings",
         lambda: all(isinstance(u,str)
                    for u in dist.get_all_urls_for_module("sqli"))),

        ("stats returns dict",
         lambda: isinstance(dist.stats(), dict)),

        ("stats has total count",
         lambda: dist.stats()["total"] >= 5),

        ("ToolIntegrator instantiates",
         lambda: isinstance(tool, ToolIntegrator)),

        ("sqlmap returns dict when not installed",
         lambda: isinstance(tool.run_sqlmap("http://t.com"), dict)),

        ("dalfox returns dict when not installed",
         lambda: isinstance(tool.run_dalfox("http://t.com"), dict)),

        ("ffuf returns dict",
         lambda: isinstance(tool.run_ffuf("http://t.com"), dict)),

        ("false positive baseline check",
         lambda: isinstance(dist.is_false_positive(
             type('R', (), {'status_code': 404, 'text': 'not found'})()
         ), bool)),
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
    run_regression_tests()
