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
        self.state          = {}   # shared state passed between steps
        self.log_lines      = []

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
            self._step05_auth,
            self._step06_intelligence,
            self._step07_attack,
            self._step08_automate,
            self._step09_chain,
            self._step10_deduplicate,
            self._step11_screenshot,
            self._step12_report,
            self._step13_h1_format,
            self._step14_knowledge,
            self._step15_llm_memory,
        ]

        for step in steps:
            try:
                step()
            except Exception as e:
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

        self.state["subdomains"] = list(subdomains)
        self.state["alive_targets"] = list(alive)
        self.log(f"Recon: {len(subdomains)} subdomains, {len(alive)} alive", "+")

    # ── STEP 03: LLM Analyze ──────────────────────────────────
    def _step03_llm_analyze(self):
        self.log("Step 03: LLM Asset Analysis")
        targets = self.state.get("alive_targets", [self.target])
        memory  = self._load_memory()

        # Build prompt for LLM
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

        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"Content-Type": "application/json"},
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=30
            )
            if r.status_code == 200:
                text = r.json()["content"][0]["text"]
                # Extract JSON
                import re
                m = re.search(r'\{.*\}', text, re.DOTALL)
                if m:
                    analysis = json.loads(m.group())
                    self.state["llm_analysis"] = analysis
                    priority = analysis.get("priority_targets", targets[:3])
                    self.state["priority_targets"] = priority
                    self.log(f"LLM: prioritized {len(priority)} targets", "+")
                    self.log(f"LLM reasoning: {analysis.get('reasoning','')[:80]}", "i")
                    return
        except Exception:
            pass

        # Fallback: use all alive targets
        self.state["priority_targets"] = targets[:5]
        self.state["llm_analysis"]     = {}
        self.log("LLM unavailable — using all targets", "~")

    # ── STEP 04: Endpoint Crawler ──────────────────────────────
    def _step04_crawl(self):
        self.log("Step 04: Endpoint Crawler")
        import re as _re
        import subprocess, shutil
        from urllib.parse import urljoin

        targets   = self.state.get("priority_targets", [self.target])
        endpoints = set()
        forms     = []
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

        self.state["endpoints"] = list(endpoints)[:200]
        self.state["forms"]     = forms[:50]
        self.log(f"Crawl: {len(endpoints)} endpoints, {len(forms)} forms", "+")

    # ── STEP 05: Auth Engine ──────────────────────────────────
    def _step05_auth(self):
        self.log("Step 05: Auth Engine")
        if not self.credentials:
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
            self.state["waf_type"]        = result.get("waf", {}).get("name", "")
            self.log(f"Intelligence: WAF={self.state['waf_type'] or 'none'}", "+")
        except Exception as e:
            self.state["intelligence"]   = {}
            self.state["bypass_headers"] = {}
            self.log(f"Intelligence partial: {e}", "~")

    # ── STEP 07: Attack Engine ────────────────────────────────
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
                inst.extra_endpoints = endpoints[:30]
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
            engine = ScreenshotEngine(str(self.output_dir / "screenshots"))
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
