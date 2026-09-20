"""
AmonStrike — Master Pipeline
15 steps. Output of each = input of next.
One URL in. H1 report out.
"""

import os
import json
import time
import sqlite3
import requests
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


try:
    from core.scope_reader import ScopeReader
    from core.duplicate_checker import DuplicateChecker
    from core.knowledge import KnowledgeBase
except Exception:
    pass

class AmonStrikePipeline:

    def __init__(self, target: str, output_dir: str = None,
                 credentials: list = None, program_handle: str = "",
                 debug: bool = False):
        self.target         = target.rstrip("/")
        self.program_handle = program_handle
        self.credentials    = credentials or []
        self.debug          = debug
        self.output_dir     = Path(output_dir or f"output/{urlparse(target).netloc}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.state          = {}
        self.log_lines      = []

        # Central scan context (shared memory across all steps)
        try:
            from core.scan_context import ScanContext
            self.scan_ctx = ScanContext(target, program_handle)
            self.state["scan_context"] = self.scan_ctx
        except Exception:
            self.scan_ctx = None

        # Decision hub (all AI decisions route through here)
        try:
            from core.decision_hub import DecisionHub
            self.hub = DecisionHub(self.scan_ctx) if self.scan_ctx else None
        except Exception:
            self.hub = None

    def log(self, msg: str, level: str = "*"):
        line = f"[{level}] {msg}"
        self.log_lines.append(line)
        print(f"  {line}")

    def run(self) -> dict:
        self.log(f"Pipeline starting: {self.target}", "*")
        t0 = time.time()

        steps = [
            self._step01_scope,
            self._step02_recon,
            self._step03_llm_analyze,
            self._step04_crawl,
            self._step04b_surface_discovery,
            self._step05_auth,
            self._step06_intelligence,
            self._step07_attack,
            self._step08_automate,
            self._step09_chain,
            self._step_iteration_loop,
            self._step10_deduplicate,
            self._step11_screenshot,
            self._step12_report,
            self._step13_h1_format,
            self._step14_knowledge,
            self._step15_llm_memory,
        ]

        # Initialize Pentesting Task Tree
        try:
            from core.task_tree import PentestTaskTree
            self.ptt = PentestTaskTree(
                self.target,
                str(self.output_dir / "ptt_session.json")
            )
            self.log(f"PTT: {self.ptt.summary()['total']} tasks from previous session", "i")
        except Exception:
            self.ptt = None

        import signal
        def _timeout_handler(signum, frame):
            raise TimeoutError("Step timed out")

        for step in steps:
            try:
                signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(120)  # 2 min max per step
                step()
                signal.alarm(0)
            except TimeoutError:
                self.log(f"{step.__name__} timed out — skipping", "!")
            except Exception as e:
                signal.alarm(0)
                self.log(f"{step.__name__} error: {e}", "!")
                if self.debug:
                    import traceback
                    traceback.print_exc()

        elapsed = time.time() - t0
        self.log(f"Pipeline complete in {elapsed:.0f}s", "+")
        self.log(f"Findings: {len(self.state.get('findings', []))}", "+")
        return self.state

    # ── STEP 01: Scope Reader ─────────────────────────────────
    def _step01_scope(self):
        self.log("Step 01: Scope Reader")
        scope = {
            "target":        self.target,
            "program_handle":self.program_handle,
            "allowed_hosts": [urlparse(self.target).netloc],
            "wildcards":     [],
            "out_of_scope":  [],
        }

        # Fetch H1 program scope if handle provided
        if self.program_handle:
            try:
                r = requests.get(
                    f"https://api.hackerone.com/v1/hackers/programs/{self.program_handle}",
                    timeout=10,
                    headers={"Accept": "application/json"}
                )
                if r.status_code == 200:
                    data  = r.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    for asset in attrs.get("structured_scope", {}).get("in_scope", []):
                        host = asset.get("asset_identifier","")
                        if host.startswith("*."):
                            scope["wildcards"].append(host)
                        elif host:
                            scope["allowed_hosts"].append(host)
                    for asset in attrs.get("structured_scope", {}).get("out_of_scope", []):
                        host = asset.get("asset_identifier","")
                        if host:
                            scope["out_of_scope"].append(host)
                    self.log(f"H1 scope loaded: {len(scope['allowed_hosts'])} assets", "+")
            except Exception:
                pass

        try:
            sr = ScopeReader(self.program_handle, self.target)
            scope["allowed_hosts"] = sr.in_scope
            scope["out_of_scope"]  = sr.out_scope
            scope["wildcards"]     = sr.wildcards
            self.state["scope_reader"] = sr
            self.log(f"Scope: {sr.summary()}", "+")
        except Exception:
            pass
        self.state["scope"] = scope
        self.log(f"Scope: {len(scope['allowed_hosts'])} in-scope hosts", "+")

    # ── STEP 02: Recon Engine ─────────────────────────────────
    def _step02_recon(self):
        self.log("Step 02: Recon Engine")
        import subprocess, shutil

        domain   = urlparse(self.target).netloc
        subdomains = set([domain])

        # subfinder
        if shutil.which("subfinder"):
            try:
                out = subprocess.run(
                    ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
                    capture_output=True, text=True, timeout=60
                ).stdout
                for line in out.strip().splitlines():
                    if line.strip():
                        subdomains.add(line.strip())
            except Exception:
                pass

        # httpx — verify which are alive
        alive = set([self.target])
        if shutil.which("httpx") and len(subdomains) > 1:
            try:
                inp  = "\n".join(subdomains)
                out  = subprocess.run(
                    ["httpx", "-silent", "-timeout", "10"],
                    input=inp, capture_output=True, text=True, timeout=120
                ).stdout
                for line in out.strip().splitlines():
                    if line.strip():
                        alive.add(line.strip())
            except Exception:
                pass

        # Wayback Machine - historical URLs with params
        try:
            import urllib.request
            domain = urlparse(self.target).netloc
            wb_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&collapse=urlkey&limit=100"
            req = urllib.request.Request(wb_url, headers={"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                wayback_urls = resp.read().decode().strip().splitlines()
                # Only keep URLs with params (attack surface)
                for u in wayback_urls:
                    if "?" in u and urlparse(u).netloc == domain:
                        subdomains.add(urlparse(u).netloc)
                        alive.add(u)
                self.log(f"Wayback: {len(wayback_urls)} historical URLs", "+")
        except Exception:
            pass

        self.state["subdomains"] = list(subdomains)
        self.state["alive_targets"] = list(alive)
        self.log(f"Recon: {len(subdomains)} subdomains, {len(alive)} alive", "+")

    # ── STEP 03: LLM Analyze ──────────────────────────────────
    def _step03_llm_analyze(self):
        self.log("Step 03: LLM Asset Analysis (Groq/Ollama)")
        targets = self.state.get("alive_targets", [self.target])
        memory  = self._load_memory()

        prompt = (
            f"You are a bug bounty expert. Analyze these targets and prioritize them.\n"
            f"Targets: {json.dumps(targets[:20])}\n"
            f"Past successful patterns: {json.dumps(memory.get('patterns', [])[:5])}\n\n"
            f"Return JSON with keys:\n"
            f"  priority_targets: list of URLs to test first (max 5)\n"
            f"  attack_hints: dict of url -> list of vuln types most likely\n"
            f"  reasoning: one sentence why\n"
            f"Return ONLY valid JSON."
        )

        # FIX #1 — Use AIBrain (Groq+Ollama+NVIDIA ensemble) not Anthropic
        try:
            from core.ai_brain import get_brain
            brain    = get_brain()
            raw      = brain.think(prompt, ensemble=False)
            analysis = self._parse_ai_json(raw)
            if analysis:
                self.state["llm_analysis"]    = analysis
                priority = analysis.get("priority_targets") or targets[:3]
                self.state["priority_targets"] = priority
                self.log(f"AI: prioritized {len(priority)} targets", "+")
                if analysis.get("reasoning"):
                    self.log(f"AI reasoning: {analysis.get('reasoning','')[:80]}", "i")
                try:
                    from core.mcts_planner import MCTSPlanner
                    plan = MCTSPlanner(time_limit=1.0).plan({"findings": []})
                    self.state["mcts_plan"] = plan
                    self.log(f"MCTS plan: {plan[:4]}", "i")
                except Exception:
                    pass
                return
            else:
                # AI responded but no parseable JSON — still use its raw text as a hint
                snippet = (raw or "").strip().replace("\n", " ")[:100]
                self.log(f"AI returned non-JSON (using all targets): {snippet}", "~")
        except Exception as e:
            self.log(f"AIBrain error: {e} — using fallback", "~")

        self.state["priority_targets"] = targets[:5]
        self.state["llm_analysis"]     = {}
        self.log("AI fallback — using all targets", "~")

    def _parse_ai_json(self, raw: str) -> dict:
        """Robustly extract a JSON object from an LLM response.
        Handles markdown fences, prose+JSON, and trailing text."""
        if not raw:
            return {}
        import re as _re
        text = raw.strip()
        # Strip ```json ... ``` fences
        fence = _re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, _re.DOTALL)
        if fence:
            try:
                return json.loads(fence.group(1))
            except Exception:
                pass
        # Greedy outermost object
        for pat in (r"\{.*\}",):
            m = _re.search(pat, text, _re.DOTALL)
            if m:
                blob = m.group()
                try:
                    return json.loads(blob)
                except Exception:
                    # Try trimming to balanced braces
                    depth = 0; end = None
                    for i, ch in enumerate(blob):
                        if ch == "{": depth += 1
                        elif ch == "}":
                            depth -= 1
                            if depth == 0:
                                end = i + 1; break
                    if end:
                        try:
                            return json.loads(blob[:end])
                        except Exception:
                            pass
        return {}

    # ── STEP 04: Endpoint Crawler ──────────────────────────────
    def _step04_crawl(self):
        self.log("Step 04: Endpoint Crawler")
        import re as _re
        import subprocess, shutil
        from urllib.parse import urljoin

        targets   = self.state.get("priority_targets", [self.target])
        # Preserve endpoints already discovered by the orchestrator / earlier steps
        endpoints = set(self.state.get("endpoints", []))
        forms     = list(self.state.get("forms", []))
        s         = requests.Session()
        s.verify  = False
        s.headers["User-Agent"] = "Mozilla/5.0"

        for target in targets[:5]:
            try:
                r = s.get(target, timeout=10)
                # Links
                for link in _re.findall(r'href=["\']([^"\'#]+)["\']', r.text):
                    abs_url = link if link.startswith("http") else urljoin(target, link)
                    if urlparse(target).netloc in abs_url:
                        endpoints.add(abs_url)
                # API calls from JS
                for api in _re.findall(r'["\'](/(?:api|v\d)[^\s"\'<>?#]+)["\']', r.text):
                    endpoints.add(urljoin(target, api))
                # Forms
                for fm in _re.finditer(r'<form([^>]*)>(.*?)</form>', r.text, _re.DOTALL | _re.I):
                    action = _re.search(r'action=["\']([^"\']+)', fm.group(1))
                    inputs = {}
                    for inp in _re.finditer(r'<input([^>]+)>', fm.group(2), _re.I):
                        name = _re.search(r'name=["\']([^"\']+)', inp.group(1))
                        if name:
                            inputs[name.group(1)] = ""
                    if action:
                        forms.append({"action": urljoin(target, action.group(1)),
                                     "inputs": inputs})
            except Exception:
                pass

        # katana if available
        if shutil.which("katana"):
            for target in targets[:3]:
                try:
                    out = subprocess.run(
                        ["katana", "-u", target, "-silent", "-d", "3", "-timeout", "10"],
                        capture_output=True, text=True, timeout=60
                    ).stdout
                    for line in out.strip().splitlines():
                        if line.strip():
                            endpoints.add(line.strip())
                except Exception:
                    pass

        self.state["endpoints"] = list(endpoints)[:500]
        self.state["forms"]     = forms[:50]
        self.log(f"Crawl: {len(endpoints)} endpoints, {len(forms)} forms", "+")

    # ── STEP 05: Auth Engine ──────────────────────────────────
    def _step05_auth(self):
        self.log("Step 05: Auth Engine")
        
        # Always try browser session first
        try:
            from core.session_manager import SessionManager
            sm      = SessionManager()
            domain  = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(self.target).netloc
            cookies = sm._grab_from_browser(domain)
            if cookies:
                self.state["sessions"] = [{
                    "username": "browser_session",
                    "role":     "user",
                    "cookies":  cookies,
                    "headers":  {"X-HackerOne-Handle": "jardani101"},
                    "user_id":  "",
                }]
                self.log(f"Session: {len(cookies)} cookies from browser", "+")
                # If we have credentials too, add them
                if not self.credentials:
                    return
        except Exception as e:
            self.log(f"Browser session: {e}", "~")

        if not self.credentials:
            if not self.state.get("sessions"):
                self.state["sessions"] = []
                self.log("No credentials — unauthenticated scan", "~")
            return

        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from core.auth_engine import ScanAuthEngine

            engine = ScanAuthEngine(self.target, timeout=15)
            for cred in self.credentials:
                engine.add_credential(
                    cred.get("username", ""),
                    cred.get("password", ""),
                    cred.get("role", "user")
                )
            engine.login_all()
            sessions = [{
                "username": s.username,
                "role":     s.role,
                "cookies":  dict(s.session.cookies),
                "headers":  s.auth_headers(),
                "user_id":  s.user_id,
            } for s in engine.get_all_sessions()]

            self.state["sessions"]    = sessions
            self.state["auth_engine"] = engine
            self.log(f"Auth: {len(sessions)} sessions active", "+")
        except Exception as e:
            self.state["sessions"] = []
            self.log(f"Auth failed: {e}", "!")

    # ── STEP 06: Intelligence ─────────────────────────────────
    def _step06_intelligence(self):
        self.log("Step 06: Intelligence")
        try:
            from intelligence.orchestrator import IntelligenceOrchestrator
            orch   = IntelligenceOrchestrator(self.target, str(self.output_dir))
            result = orch.run()
            self.state["intelligence"]    = result
            self.state["bypass_headers"]  = result.get("bypass_headers", {})
            waf = result.get("waf", "")
            self.state["waf_type"]        = waf if isinstance(waf, str) else waf.get("name", "")
            self.log(f"Intelligence: WAF={self.state['waf_type'] or 'none'}", "+")
        except Exception as e:
            self.state["intelligence"]   = {}
            self.state["bypass_headers"] = {}
            self.log(f"Intelligence partial: {e}", "~")

    # ── STEP 07: Attack Engine ────────────────────────────────
    def _step04b_surface_discovery(self):
        """Aggressive surface discovery - finds real API endpoints."""
        self.log("Step 04b: Aggressive Surface Discovery + JS Analysis + WAF Detection")
        try:
            from core.surface_discovery import AggressiveSurfaceDiscovery
            import requests, urllib3; urllib3.disable_warnings()
            s = requests.Session(); s.verify = False
            s.headers.update({
                "User-Agent": "Mozilla/5.0",
                "X-Hackerone": "jardani101",
            })
            for h, v in self.state.get("required_headers", {}).items():
                s.headers[h] = v

            disc   = AggressiveSurfaceDiscovery(self.target, s,
                         self.state.get("required_headers", {}))
            result = disc.run()

            existing = set(self.state.get("endpoints", []))
            new_eps  = set(result.get("endpoints", []))
            api_eps  = set(result.get("api_calls", []))
            all_eps  = existing | new_eps | api_eps
            self.state["endpoints"] = list(all_eps)

            for item in result.get("interesting", []):
                if item.get("type") == "sensitive_data_in_response":
                    self.log(f"Sensitive data in: {item.get('url','')[:60]}", "!")
                elif item.get("type") == "sensitive_file":
                    self.log(f"Exposed file: {item.get('path','')} ({item.get('size',0)}b)", "!")
                elif item.get("type") == "possible_secret":
                    self.log(f"Possible secret in JS: {item.get('value','')[:40]}", "!")
                    self.state.setdefault("findings", []).append({
                        "title":       "Possible Secret/API Key Exposed in JS File",
                        "severity":    "HIGH",
                        "module":      "intelligence",
                        "url":         item.get("source",""),
                        "description": "Potential secret found hardcoded in JavaScript file.",
                        "evidence":    f"Value: {item.get('value','')}\nSource: {item.get('source','')}",
                        "remediation": "Remove secrets from JS. Use environment variables.",
                        "cve":         "CWE-798",
                    })

            self.log(f"Surface: {len(all_eps)} total endpoints discovered", "+")

            # FIX #3 — WAF detection + bypass
            try:
                from core.waf_bypass import WAFBypass
                waf = WAFBypass(s)
                waf_type = waf.detect(self.target)
                self.state["waf_type"]    = waf_type
                self.state["waf_bypass"]  = waf
                self.log(f"WAF detected: {waf_type or 'none'}", "+")

                # If WAF present, hunt for origin IP to bypass it entirely
                if waf_type:
                    try:
                        from core.waf_bypass import OriginFinder
                        from urllib.parse import urlparse as _up
                        dom = _up(self.target).netloc or self.target
                        origin = OriginFinder(s).find(dom)
                        if origin.get("verified_ip"):
                            self.state["origin_ip"] = origin["verified_ip"]
                            self.log(f"ORIGIN FOUND behind {waf_type}: "
                                     f"{origin['verified_ip']} — WAF bypassed", "+")
                            self.state.setdefault("findings", []).append({
                                "title":    f"Origin IP Exposure — {waf_type} WAF bypass",
                                "severity": "MEDIUM",
                                "module":   "origin_finder",
                                "type":     "waf_bypass",
                                "url":      self.target,
                                "description": (
                                    f"The origin server IP {origin['verified_ip']} is "
                                    f"reachable directly, bypassing the {waf_type} WAF. "
                                    f"An attacker can attack the origin without WAF protection."
                                ),
                                "evidence": f"Verified via Host-header match: {origin['verified_ip']}",
                                "remediation": "Restrict origin to only accept traffic from the WAF/CDN IP ranges.",
                                "timestamp": datetime.now().isoformat(),
                            })
                        elif origin.get("origin_ips"):
                            self.log(f"Candidate origins (unverified): "
                                     f"{origin['origin_ips'][:5]}", "i")
                    except Exception as e:
                        self.log(f"Origin finder: {e}", "~")
            except Exception as e:
                self.log(f"WAF detect: {e}", "~")

            # FIX #3 — JS intelligence (hidden endpoints, secrets, GraphQL)
            try:
                from core.js_analyzer import JSAnalyzer
                js = JSAnalyzer(self.target, s)
                js_result = js.scan()
                for ep in js_result.get("endpoints", []):
                    self.state["endpoints"].append(ep)
                for secret in js_result.get("secrets", []):
                    self.state.setdefault("findings", []).append({
                        "title":       f"Secret in JS: {secret['type']}",
                        "severity":    "HIGH",
                        "module":      "js_analyzer",
                        "url":         self.target,
                        "description": f"JS intelligence found {secret['type']}",
                        "evidence":    secret["value"],
                        "remediation": "Remove secrets from client-side code.",
                    })
                if js_result.get("graphql"):
                    self.state["has_graphql"] = True
                self.log(f"JS: {len(js_result['endpoints'])} endpoints, {len(js_result['secrets'])} secrets", "+")
            except Exception as e:
                self.log(f"JS analysis: {e}", "~")

            # FIX #4 — GitHub OSINT
            try:
                from core.github_osint import GitHubOSINT
                from urllib.parse import urlparse as _up
                domain = _up(self.target).netloc
                gh = GitHubOSINT()
                gh_result = gh.full_scan(domain)
                for f in gh_result.get("findings", []):
                    self.state.setdefault("findings", []).append({
                        "title":       f"GitHub: {f.get('secret_type', f.get('query',''))}",
                        "severity":    f.get("severity","HIGH"),
                        "module":      "github_osint",
                        "url":         f.get("url", self.target),
                        "description": f"Secret/credential found in GitHub repo: {f.get('repo','')}",
                        "evidence":    f"File: {f.get('file','')} Value: {f.get('value','')}",
                        "remediation": "Rotate all exposed credentials immediately.",
                    })
                orgs = gh_result.get("orgs", [])
                if orgs:
                    self.log(f"GitHub OSINT: orgs={orgs} findings={len(gh_result['findings'])}", "+")
            except Exception as e:
                self.log(f"GitHub OSINT: {e}", "~")

            # Brain-driven tool sourcing: install missing tools for this target
            try:
                from core.kali_tools import KaliToolsMaximizer
                km   = KaliToolsMaximizer()
                tech = self.state.get("tech_stack", []) or [self.state.get("waf_type","")]
                vcls = ["sqli","xss","ssrf","idor","crawl","params","secrets","vuln_scan"]
                rec  = km.recommend_for_target(tech, vcls, auto_install=True)
                if rec.get("installed"):
                    self.log(f"Tool sourcing: installed {rec['installed']}", "+")
                elif rec.get("missing"):
                    self.log(f"Tool gaps (run hunt.py --install-tools): "
                             f"{list(rec['missing'].keys())[:6]}", "i")
            except Exception as e:
                self.log(f"Tool sourcing: {e}", "~")

        except Exception as e:
            self.log(f"Surface discovery: {e}", "~")

    def _step07_attack(self):
        self.log("Step 07: Attack Engine")
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

        endpoints = self.state.get("endpoints", [])
        sessions  = self.state.get("sessions", [])
        cookies   = sessions[0]["cookies"] if sessions else {}
        headers   = sessions[0]["headers"] if sessions else {}
        findings  = []

        modules = [
            ("modules.sqli",            "SqliModule"),
            ("modules.xss",             "XssModule"),
            ("modules.cors",            "CorsModule"),
            ("modules.idor",            "IdorModule"),
            ("modules.lfi",             "LfiModule"),
            ("modules.ssrf",            "SsrfModule"),
            ("modules.headers",         "HeadersModule"),
            ("modules.cookies",         "CookiesModule"),
            ("modules.open_redirect",   "OpenRedirectModule"),
            ("modules.clickjacking",    "ClickjackingModule"),
            ("modules.rate_limit",      "RateLimitModule"),
            ("modules.nosql_injection", "NosqlInjectionModule"),
            ("modules.file_upload",     "FileUploadModule"),
            ("modules.error_disclosure","ErrorDisclosureModule"),
            ("modules.account_takeover","AccountTakeoverModule"),
            ("modules.cors",            "CorsModule"),
            ("modules.twofa_bypass",    "TwofaBypassModule"),
            ("modules.command_injection","CommandInjectionModule"),
            ("modules.csrf",            "CsrfModule"),
        ]

        for mod_path, cls_name in modules:
            try:
                mod  = __import__(mod_path, fromlist=[cls_name])
                cls  = getattr(mod, cls_name)
                inst = cls(url=self.target, timeout=10,
                          cookies=cookies, headers=headers)
                # Pass ALL discovered endpoints - not just 30
                all_endpoints = list(set(
                    endpoints +
                    self.state.get("endpoints", []) +
                    list(self.state.get("api_calls", {}).keys() if isinstance(self.state.get("api_calls"), dict) else self.state.get("api_calls", []))
                ))
                inst.extra_endpoints = all_endpoints[:100]
                # Apply WAF bypass headers
                if self.state.get("waf_type"):
                    inst._waf_type = self.state["waf_type"]
                # Apply required headers (e.g. X-Hackerone)
                for h, v in self.state.get("required_headers", {}).items():
                    inst.session.headers[h] = v
                result = inst.run()
                n = len(result.get("findings", []))
                for f in result.get("findings", []):
                    f.setdefault("module", mod_path.split(".")[1])
                    f.setdefault("timestamp", datetime.now().isoformat())
                findings.extend(result.get("findings", []))
                if n:
                    self.log(f"  [{mod_path.split('.')[1]}] {n} findings", "+")
            except Exception as e:
                if self.debug:
                    self.log(f"  [{mod_path.split('.')[1]}] error: {e}", "!")

        # Run false positive validator on all findings
        try:
            from core.fp_validator import FalsePositiveValidator
            import requests as _req
            r0 = _req.get(self.target, timeout=8, verify=False,
                         headers={"User-Agent":"Mozilla/5.0"})
            validator = FalsePositiveValidator(r0.text if r0 else "")
            before = len(findings)
            findings = validator.validate_all(findings)
            removed = before - len(findings)
            if removed:
                self.log(f"FP filter: removed {removed} false positives", "i")
                for t in validator.summary()["rejected_titles"]:
                    self.log(f"  Rejected: {t[:60]}", "i")
        except Exception as e:
            self.log(f"FP validator: {e}", "~")

        self.state["findings"] = findings
        # Run custom attacks (novel attack classes)
        try:
            from core.custom_attacks import CustomAttackEngine, install_builtin_attacks
            install_builtin_attacks()
            cookies = sessions[0]["cookies"] if sessions else {}
            heads   = sessions[0]["headers"] if sessions else {}
            ca_engine = CustomAttackEngine(self.target, cookies, heads)
            ca_findings = ca_engine.run_all()
            for f in ca_findings:
                f.setdefault("timestamp", datetime.now().isoformat())
            findings.extend(ca_findings)
            if ca_findings:
                self.log(f"Custom attacks: {len(ca_findings)} findings", "+")
        except Exception as e:
            self.log(f"Custom attacks: {e}", "~")

        # Nuclei scan - 12,000+ community templates
        try:
            import shutil
            if shutil.which("nuclei"):
                import subprocess, json as _json
                nuclei_out = subprocess.run(
                    ["nuclei", "-u", self.target, "-silent",
                     "-severity", "critical,high,medium",
                     "-json", "-timeout", "10", "-rate-limit", "10"],
                    capture_output=True, text=True, timeout=120
                )
                for line in nuclei_out.stdout.strip().splitlines():
                    try:
                        n = _json.loads(line)
                        findings.append({
                            "title":       n.get("info",{}).get("name","Nuclei Finding"),
                            "severity":    n.get("info",{}).get("severity","MEDIUM").upper(),
                            "module":      "nuclei",
                            "url":         n.get("matched-at", self.target),
                            "description": n.get("info",{}).get("description",""),
                            "evidence":    "Template: " + n.get('template-id','') + "\nMatcher: " + n.get('matcher-name',''),
                            "remediation": n.get("info",{}).get("remediation",""),
                            "cve":         ",".join(n.get("info",{}).get("classification",{}).get("cve-id",[])),
                            "timestamp":   datetime.now().isoformat(),
                        })
                    except Exception:
                        pass
                nuclei_count = len([f for f in findings if f.get("module")=="nuclei"])
                if nuclei_count:
                    self.log(f"Nuclei: {nuclei_count} findings from 12k templates", "+")
            else:
                self.log("Nuclei not installed — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "~")
        except Exception as e:
            self.log(f"Nuclei: {e}", "~")

        # FIX #5 — Behavioral fuzzing on discovered endpoints with params
        try:
            from core.behavioral_fuzzer import BehavioralFuzzer
            import requests as _req2, urllib3 as _ul2; _ul2.disable_warnings()
            fuzz_session = _req2.Session(); fuzz_session.verify = False
            fuzz_session.headers["User-Agent"] = "Mozilla/5.0"
            fuzzer = BehavioralFuzzer()
            fuzz_targets = [ep for ep in self.state.get("endpoints",[]) if "=" in ep][:10]
            diff_engine_inst = None
            try:
                from core.diff_engine import DiffEngine
                diff_engine_inst = DiffEngine(z_threshold=3.0)
            except Exception:
                pass
            for ep in fuzz_targets:
                for payload in fuzzer.boundary_payloads("string")[:5]:
                    try:
                        r = fuzz_session.get(ep + payload, timeout=8)
                        if diff_engine_inst:
                            # FIX #6 — Record baseline then detect anomalies
                            diff_engine_inst.record(ep, r)
                            anomaly = diff_engine_inst.is_anomaly(ep, r)
                            if anomaly.get("zero_day_candidate"):
                                findings.append({
                                    "title":       f"Zero-Day Candidate: Anomalous response at {ep}",
                                    "severity":    "HIGH",
                                    "module":      "diff_engine",
                                    "url":         ep,
                                    "description": f"Z-score anomaly detected: {anomaly['anomalies']}",
                                    "evidence":    str(anomaly),
                                    "remediation": "Manual investigation required.",
                                    "timestamp":   datetime.now().isoformat(),
                                })
                    except Exception:
                        pass
            self.log(f"Behavioral fuzzing complete on {len(fuzz_targets)} endpoints", "+")
        except Exception as e:
            self.log(f"Behavioral fuzzer: {e}", "~")

        # FIX #7 — Neural KB reinforcement learning
        try:
            from core.neural_kb import NeuralKB
            kb = NeuralKB()
            for f in findings:
                pattern_id = f.get("module","")
                if pattern_id:
                    kb.reinforce(pattern_id, success=True)
            self.log(f"NeuralKB reinforced with {len(findings)} findings", "i")
        except Exception as e:
            self.log(f"NeuralKB: {e}", "~")

        self.state["findings"] = findings
        self.log(f"Attack: {len(findings)} real findings", "+")

    # ── STEP 08: Automate Engine (IDOR/Auth bypass) ───────────
    def _step08_automate(self):
        self.log("Step 08: AutomateEngine (session replay)")
        sessions = self.state.get("sessions", [])
        if len(sessions) < 1:
            self.log("No sessions — skipping automate", "~")
            return

        try:
            from core.automate_engine import AutomateEngine
            engine = AutomateEngine(
                self.target,
                credentials=self.credentials,
                max_pages=50,
                timeout=15,
            )
            result = engine.run()
            new_findings = result.get("findings", [])
            self.state["findings"].extend(new_findings)
            self.log(f"Automate: {len(new_findings)} additional findings", "+")
        except Exception as e:
            self.log(f"Automate error: {e}", "~")

        # Multi-agent validation: exploit proof + business logic + MITRE mapping
        try:
            from core.agents import AgentOrchestrator
            sessions = self.state.get("sessions", [])
            orch = AgentOrchestrator(self.target, sessions)
            agent_result = orch.run(self.state.get("findings", []))
            self.state["findings"] = agent_result["findings"]
            self.state["app_model"] = agent_result.get("app_model", {})
            dropped = agent_result.get("dropped", 0)
            confirmed = agent_result.get("confirmed", 0)
            if dropped:
                self.log(f"Agents: {dropped} unproven findings dropped", "i")
            self.log(f"Agents: {confirmed} findings with proof, MITRE ATT&CK mapped", "+")
        except Exception as e:
            self.log(f"Agents: {e}", "~")

    # ── STEP 09: Chain Engine ─────────────────────────────────
    def _step09_chain(self):
        self.log("Step 09: Chain Engine")
        try:
            from intelligence.chain_engine import ChainEngine
            engine = ChainEngine(self.target)
            chains = engine.analyze(self.state.get("findings", []))
            self.state["chains"] = chains
            if chains:
                self.log(f"Chains: {len(chains)} vulnerability chains found", "+")
                for c in chains[:3]:
                    self.log(f"  {c.get('name','')} (${c.get('estimated_bounty',0):,})", "+")
        except Exception as e:
            self.state["chains"] = []
            self.log(f"Chain engine: {e}", "~")

    # ── STEP 10: Duplicate Checker ────────────────────────────
    def _step_iteration_loop(self):
        """PentestGPT-style iteration - keep running until no new findings."""
        if not hasattr(self, 'ptt') or not self.ptt:
            return
        pending = self.ptt.get_next_tasks(limit=5)
        if not pending:
            return
        self.log(f"Iteration loop: {len(pending)} follow-up tasks from PTT", "i")
        import sys; sys.path.insert(0, '.')
        for task in pending[:3]:
            try:
                mod_path = f"modules.{task.module}"
                cls_name = "".join(w.capitalize() for w in task.module.split("_")) + "Module"
                mod = __import__(mod_path, fromlist=[cls_name])
                cls = getattr(mod, cls_name)
                sessions = self.state.get("sessions", [])
                cookies = sessions[0]["cookies"] if sessions else {}
                headers = sessions[0]["headers"] if sessions else {}
                inst = cls(url=task.target_url, timeout=8, cookies=cookies, headers=headers)
                res = inst.run()
                new_findings = res.get("findings", [])
                for f in new_findings:
                    f.setdefault("module", task.module)
                    f.setdefault("timestamp", datetime.now().isoformat())
                    f["spawned_by"] = task.title
                self.state["findings"].extend(new_findings)
                self.ptt.complete_task(task.id, new_findings[0] if new_findings else None)
                if new_findings:
                    self.log(f"  PTT task '{task.title[:40]}': {len(new_findings)} findings", "+")
            except Exception as e:
                if self.debug: self.log(f"PTT task error: {e}", "!")
                self.ptt.fail_task(task.id, str(e))

    def _step10_deduplicate(self):
        self.log("Step 10: Duplicate Checker")
        findings = self.state.get("findings", [])
        if not findings:
            return

        unique = []
        for f in findings:
            # Local dedup — same title + url
            sig = hashlib.md5(f"{f.get('title','')}|{f.get('url','')}".encode()).hexdigest()
            if not any(hashlib.md5(f"{x.get('title','')}|{x.get('url','')}".encode()).hexdigest() == sig
                      for x in unique):
                unique.append(f)

        # H1 Hacktivity dedup (if program handle provided)
        if self.program_handle:
            try:
                r = requests.get(
                    f"https://hackerone.com/{self.program_handle}/hacktivity.json",
                    timeout=10,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if r.status_code == 200:
                    known = [item.get("title","").lower()
                            for item in r.json().get("data", [])]
                    before = len(unique)
                    unique = [f for f in unique
                             if not any(
                                 w in f.get("title","").lower()
                                 for w in known[:50]
                                 if len(w) > 5
                             )]
                    self.log(f"H1 dedup: removed {before - len(unique)} likely duplicates", "i")
            except Exception:
                pass

        removed = len(findings) - len(unique)

        # Duplicate checker against H1 Hacktivity
        try:
            dc = DuplicateChecker(self.program_handle)
            unique, dupes = dc.filter(unique)
            removed += dupes
        except Exception:
            pass

        self.state["findings"] = unique
        self.log(f"Dedup: {len(unique)} unique findings ({removed} removed)", "+")

    # ── STEP 11: Screenshot ───────────────────────────────────
    def _step11_screenshot(self):
        self.log("Step 11: Screenshots")
        findings = self.state.get("findings", [])
        targets  = [f for f in findings if f.get("severity") in ["CRITICAL","HIGH"]][:5]

        if not targets:
            return

        try:
            from verify.screenshot import ScreenshotEngine
            engine = ScreenshotEngine(self.target, str(self.output_dir / "screenshots"))
            for f in targets:
                try:
                    shot = engine.capture(f.get("url",""))
                    if shot:
                        f.setdefault("screenshots", [])
                        f["screenshots"].append(shot)
                except Exception:
                    pass
            self.log(f"Screenshots: captured for {len(targets)} findings", "+")
        except Exception as e:
            self.log(f"Screenshots unavailable: {e}", "~")

    # ── STEP 12: Report Generator ─────────────────────────────
    def _step12_report(self):
        self.log("Step 12: Report Generator")
        try:
            from reports.generator import ReportGenerator
            scan_id = f"{urlparse(self.target).netloc}_{int(time.time())}"
            gen     = ReportGenerator(scan_id, self.target, str(self.output_dir))
            gen.add_findings(self.state.get("findings", []))
            for chain in self.state.get("chains", []):
                gen.add_chain(chain)
            paths = gen.generate_all()
            self.state["reports"] = paths
            for fmt, path in paths.items():
                size = os.path.getsize(path) if os.path.exists(path) else 0
                self.log(f"Report {fmt.upper()}: {size:,}b → {path}", "+")
        except Exception as e:
            self.log(f"Report error: {e}", "!")

    # ── STEP 13: H1 Formatter ─────────────────────────────────
    def _step13_h1_format(self):
        self.log("Step 13: H1 Submission Portal")
        try:
            from reports.hackerone_format import generate_h1_package
            pkg = generate_h1_package(
                self.state.get("findings", []),
                str(self.output_dir),
                program_handle=self.program_handle,
                target_url=self.target,
            )
            self.state["h1_package"] = pkg
            if pkg.get("portal"):
                self.log(f"H1 Portal: {pkg['portal']} ({pkg.get('count',0)} submissions)", "+")
        except Exception as e:
            self.log(f"H1 formatter error: {e}", "!")

    # ── STEP 14: Knowledge Writer ──────────────────────────────
    def _step14_knowledge(self):
        self.log("Step 14: Knowledge DB")
        memory = self._load_memory()

        findings = self.state.get("findings", [])
        target   = urlparse(self.target).netloc

        # Record what worked
        for f in findings:
            if f.get("severity") in ["CRITICAL", "HIGH"]:
                pattern = {
                    "module":    f.get("module", ""),
                    "parameter": f.get("parameter", ""),
                    "payload":   str(f.get("payload", ""))[:100],
                    "severity":  f.get("severity", ""),
                    "tech":      self.state.get("intelligence", {}).get("tech", ""),
                    "waf":       self.state.get("waf_type", ""),
                    "target":    target,
                    "timestamp": datetime.now().isoformat(),
                }
                memory.setdefault("patterns", [])
                if pattern not in memory["patterns"]:
                    memory["patterns"].append(pattern)

        # Record target profile
        memory.setdefault("targets", {})
        memory["targets"][target] = {
            "last_scanned":  datetime.now().isoformat(),
            "findings_count":len(findings),
            "waf":           self.state.get("waf_type", ""),
            "subdomains":    len(self.state.get("subdomains", [])),
        }

        # Keep only last 500 patterns
        memory["patterns"] = memory["patterns"][-500:]
        self._save_memory(memory)
        self.state["memory"] = memory
        # Use KnowledgeBase class
        try:
            kb = KnowledgeBase()
            for f in findings:
                if f.get("severity") in ["CRITICAL","HIGH"]:
                    kb.record_finding(f, urlparse(self.target).netloc)
            hints = kb.get_hints(self.target)
            self.state["next_hints"] = hints
            for h in hints:
                self.log(f"KB hint: {h}", "i")
        except Exception:
            pass
        self.log(f"Knowledge: {len(memory.get('patterns',[]))} patterns stored", "+")

    # ── STEP 15: LLM Memory Layer ──────────────────────────────
    def _step15_llm_memory(self):
        self.log("Step 15: LLM Memory Synthesis")
        memory   = self.state.get("memory", {})
        findings = self.state.get("findings", [])

        if not findings:
            return

        # Ask LLM to synthesize learnings
        prompt = (
            f"Security scan complete. Findings:\n"
            f"{json.dumps([{'title':f.get('title'),'severity':f.get('severity'),'module':f.get('module')} for f in findings[:10]], indent=2)}\n\n"
            f"Target: {self.target}\n"
            f"WAF: {self.state.get('waf_type','none')}\n\n"
            f"In 3 bullet points, what should I test FIRST on the NEXT similar target? "
            f"Return JSON: {{\"next_scan_hints\": [\"hint1\", \"hint2\", \"hint3\"]}}"
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
                import re
                m = re.search(r'\{.*\}', text, re.DOTALL)
                if m:
                    hints = json.loads(m.group()).get("next_scan_hints", [])
                    memory["next_scan_hints"] = hints
                    self._save_memory(memory)
                    for h in hints:
                        self.log(f"LLM hint: {h}", "i")
        except Exception:
            pass

    # ── Memory store ──────────────────────────────────────────
    def _memory_path(self) -> Path:
        p = Path.home() / ".amonstrike" / "knowledge.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _load_memory(self) -> dict:
        try:
            return json.loads(self._memory_path().read_text())
        except Exception:
            return {"patterns": [], "targets": {}, "next_scan_hints": []}

    def _save_memory(self, memory: dict):
        self._memory_path().write_text(json.dumps(memory, indent=2, default=str))


# ── CLI ───────────────────────────────────────────────────────

def run_regression_tests():
    print("\n=== PIPELINE REGRESSION TESTS ===")
    passed = failed = 0

    tests = [
        ("Pipeline instantiates",
         lambda: isinstance(AmonStrikePipeline("http://test.com"), AmonStrikePipeline)),
        ("Memory load returns dict",
         lambda: isinstance(AmonStrikePipeline("http://t.com")._load_memory(), dict)),
        ("Memory save works",
         lambda: (AmonStrikePipeline("http://t.com")._save_memory({"patterns":[]}) or True)),
        ("Output dir created",
         lambda: AmonStrikePipeline("http://t.com", "/tmp/amon_pipe_test").output_dir.exists()),
        ("State dict initialized",
         lambda: isinstance(AmonStrikePipeline("http://t.com").state, dict)),
        ("Scope step runs",
         lambda: (AmonStrikePipeline("http://t.com")._step01_scope() or True)),
        ("Scope state populated",
         lambda: (lambda p: (p._step01_scope(), "scope" in p.state)[1])(AmonStrikePipeline("http://t.com"))),
        ("Credentials passed through",
         lambda: AmonStrikePipeline("http://t.com", credentials=[{"username":"a","password":"b"}]).credentials != []),
        ("Program handle stored",
         lambda: AmonStrikePipeline("http://t.com", program_handle="hackerone").program_handle == "hackerone"),
        ("Dedup removes duplicates",
         lambda: (lambda p: (
             p.state.__setitem__("findings", [
                 {"title":"SQLi","url":"http://t.com","severity":"HIGH"},
                 {"title":"SQLi","url":"http://t.com","severity":"HIGH"},
             ]),
             p._step10_deduplicate(),
             len(p.state["findings"]) == 1
         )[2])(AmonStrikePipeline("http://t.com"))),
    ]

    for name, fn in tests:
        try:
            if fn(): passed += 1; print(f"  ✓ {name}")
            else: failed += 1; print(f"  ✗ {name}")
        except Exception as e:
            failed += 1; print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        run_regression_tests()
    elif len(sys.argv) > 1:
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("url")
        p.add_argument("--program", default="")
        p.add_argument("--credentials", default="[]")
        p.add_argument("--output", default=None)
        p.add_argument("--debug", action="store_true")
        args = p.parse_args()
        creds = json.loads(args.credentials)
        pipeline = AmonStrikePipeline(
            args.url, args.output, creds, args.program, args.debug
        )
        pipeline.run()
    else:
        print("Usage: python3 core/pipeline.py <url> [--program handle] [--credentials JSON]")
