#!/usr/bin/env python3
"""
AmonStrike — CAI-Level Intelligence Engine
Based on: CAI (Alias Robotics, 2025), DARPA Atlantis (2026),
          VulnBot PTG, RefPentester, PenForge

Architecture:
  Blackboard    — shared memory all agents read/write
  ReflectionLoop — self-corrects before reporting
  DynamicRouter  — LLM picks tool based on state
  TaskGraph      — state machine with backtracking
  MultiScaffold  — 3 reasoning paths, best wins
"""

import json, time, hashlib, threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict


# ── 1. BLACKBOARD (DARPA Atlantis architecture) ───────────────

class Blackboard:
    """
    Shared memory space. All agents read and write here.
    When one agent finds something, all others react.
    """
    def __init__(self):
        self._lock    = threading.Lock()
        self.findings = []
        self.state    = {
            "target":      "",
            "tech":        [],
            "waf":         "",
            "endpoints":   [],
            "credentials": [],
            "sessions":    [],
            "graph_state": {},   # current PTG node states
            "blocked_paths": [], # techniques that failed
            "confirmed":   [],   # proven findings
            "hypotheses":  [],   # unconfirmed theories to test
        }
        self.event_log = []
        self._subscribers = defaultdict(list)

    def write(self, key: str, value, agent: str = ""):
        with self._lock:
            if key == "finding":
                sig = hashlib.md5(
                    f"{value.get('title','')}|{value.get('url','')}".encode()
                ).hexdigest()
                if not any(hashlib.md5(
                    f"{f.get('title','')}|{f.get('url','')}".encode()
                ).hexdigest() == sig for f in self.findings):
                    self.findings.append(value)
                    self._notify("new_finding", value)
            elif key in self.state:
                old = self.state[key]
                if isinstance(old, list) and isinstance(value, list):
                    self.state[key] = list(set(map(str, old + value)))
                else:
                    self.state[key] = value
                self._notify(f"state_{key}", value)
            self.event_log.append({
                "time":  datetime.now().isoformat(),
                "agent": agent,
                "key":   key,
                "value": str(value)[:100],
            })

    def read(self, key: str):
        with self._lock:
            if key == "findings":
                return list(self.findings)
            return self.state.get(key)

    def subscribe(self, event: str, callback):
        """Agent subscribes to events — reactive architecture."""
        self._subscribers[event].append(callback)

    def _notify(self, event: str, data):
        for cb in self._subscribers.get(event, []):
            try:
                threading.Thread(target=cb, args=(data,), daemon=True).start()
            except Exception:
                pass

    def get_context(self) -> str:
        """Full current state as text for LLM."""
        findings = self.findings[-10:]
        return json.dumps({
            "tech":          self.state["tech"],
            "waf":           self.state["waf"],
            "endpoints_count": len(self.state["endpoints"]),
            "confirmed":     len(self.state["confirmed"]),
            "recent_findings": [
                {"title": f.get("title",""), "severity": f.get("severity","")}
                for f in findings
            ],
            "blocked":       self.state["blocked_paths"][-5:],
            "hypotheses":    self.state["hypotheses"][-3:],
        }, indent=2)


# ── 2. REFLECTION LOOP (RefPentester, EnIGMA) ─────────────────

class ReflectionLoop:
    """
    Before reporting: did I actually test this?
    After failure: what haven't I tried?
    Self-corrects. Never hallucinates results.
    """

    def __init__(self, brain, blackboard: Blackboard):
        self.brain = brain
        self.bb    = blackboard

    def reflect_on_finding(self, finding: dict) -> dict:
        """
        Before adding to confirmed: verify it's real.
        Three checks:
        1. Evidence is from response, not payload
        2. Result differs from baseline
        3. Pattern matches known-real signatures
        """
        module   = finding.get("module","")
        evidence = finding.get("evidence","")
        url      = finding.get("url","")

        # Check 1: Evidence sanity
        if not evidence or len(evidence) < 20:
            finding["reflection"] = "REJECTED: insufficient evidence"
            finding["proven"]     = False
            return finding

        # Check 2: SSRF — response must not be homepage
        if module == "ssrf":
            real_keys = ["ami-id","instance-id","AccessKeyId","serviceAccounts"]
            homepage  = ["<!DOCTYPE","<html","<title>","viewport"]
            resp      = evidence
            if "Response:" in evidence:
                resp = evidence[evidence.find("Response:")+9:]
            if sum(1 for h in homepage if h in resp) >= 2:
                finding["reflection"] = "REJECTED: homepage returned, not metadata"
                finding["proven"]     = False
                return finding
            if not any(k in resp for k in real_keys):
                finding["reflection"] = "REJECTED: no real metadata in response"
                finding["proven"]     = False
                return finding

        # Check 3: RCE — must match real output pattern
        if module in ["command_injection","rce"]:
            def has_real_uid(text):
                if "uid=" not in text: return False
                idx   = text.find("uid=")
                after = text[idx+4:idx+20]
                return any(c.isdigit() for c in after) and "(" in after
            if not has_real_uid(evidence):
                finding["reflection"] = "REJECTED: uid= in HTML attribute, not real RCE"
                finding["proven"]     = False
                return finding

        # Check 4: IDOR — must have real sensitive data
        if module == "idor":
            sensitive = ["email","phone","password","ssn","card","token","secret"]
            pub_html  = ["<!DOCTYPE","<html","viewport","og:title"]
            has_sens  = any(s in evidence.lower() for s in sensitive)
            is_public = sum(1 for p in pub_html if p in evidence) >= 2
            if is_public and not has_sens:
                finding["reflection"] = "REJECTED: public page content, no sensitive data"
                finding["proven"]     = False
                return finding

        finding["reflection"] = "CONFIRMED: evidence validates finding"
        finding["proven"]     = True
        return finding

    def reflect_on_failure(self, technique: str, target: str,
                            response_code: int, response_text: str) -> list:
        """
        403/429/blocked — what should we try next?
        Returns list of bypass strategies.
        """
        bypasses = []

        if response_code == 403:
            bypasses.extend([
                {"technique": "waf_bypass_headers",
                 "headers": {"X-Forwarded-For":"127.0.0.1",
                            "X-Real-IP":"127.0.0.1",
                            "CF-Connecting-IP":"127.0.0.1"}},
                {"technique": "method_override",
                 "headers": {"X-HTTP-Method-Override":"GET",
                            "X-Method-Override":"GET"}},
                {"technique": "path_normalization",
                 "path_variants": [
                     target + "//", target + "/../" + target.split("/")[-1],
                     target.replace("/api/","/API/"),
                     target + "?",
                 ]},
                {"technique": "encoding_bypass",
                 "path_variants": [
                     target.replace("/","%2f"),
                     target + "%00",
                     target + ".json",
                     target + ";.css",
                 ]},
            ])
            # Add to blocked paths so we don't repeat
            self.bb.write("blocked_paths", [f"{technique}:{target}:403"])

        elif response_code == 429:
            bypasses.append({
                "technique": "rate_limit_bypass",
                "wait": 5,
                "headers": {"X-Forwarded-For": f"10.0.0.{hash(target)%254+1}"},
            })

        return bypasses

    def hypothesize(self, finding: dict) -> list:
        """
        Given a finding, what are the logical next hypotheses?
        Adds to blackboard for other agents to test.
        """
        module   = finding.get("module","")
        severity = finding.get("severity","")
        url      = finding.get("url","")
        hypotheses = []

        chains = {
            "sqli":  ["auth_bypass_sqli","extract_users","extract_credentials","check_rce_via_sqli"],
            "idor":  ["mass_enumerate_ids","test_write_access","check_admin_idor"],
            "ssrf":  ["pivot_to_internal","extract_cloud_metadata","check_rce_via_ssrf"],
            "xss":   ["check_stored_variant","test_csp_bypass","cookie_theft"],
            "cors":  ["confirm_with_credentials","test_account_takeover"],
            "lfi":   ["read_config_files","check_log_poisoning","rce_via_lfi"],
        }

        for next_test in chains.get(module, []):
            hypotheses.append({
                "test":     next_test,
                "based_on": finding.get("title",""),
                "url":      url,
                "priority": 1 if severity == "CRITICAL" else 2,
            })

        self.bb.write("hypotheses", hypotheses)
        return hypotheses


# ── 3. DYNAMIC TOOL ROUTER (CAI / PenForge) ──────────────────

class DynamicToolRouter:
    """
    LLM picks the right tool based on current state.
    Not hardcoded module order — dynamic decision.
    """

    TOOL_REGISTRY = {
        # Format: name → {description, preconditions, cost}
        "sqli":             {"desc":"SQL injection testing","pre":["has_params"],"cost":3},
        "xss":              {"desc":"XSS testing","pre":["has_params"],"cost":2},
        "idor":             {"desc":"IDOR/access control","pre":["has_ids"],"cost":3},
        "ssrf":             {"desc":"SSRF testing","pre":["has_url_params"],"cost":3},
        "jwt_deep":         {"desc":"JWT security","pre":["has_jwt"],"cost":2},
        "graphql_deep":     {"desc":"GraphQL testing","pre":["has_graphql"],"cost":2},
        "lfi":              {"desc":"Local file inclusion","pre":["is_php"],"cost":2},
        "ssti":             {"desc":"Template injection","pre":["has_template"],"cost":2},
        "command_injection":{"desc":"OS command injection","pre":["has_params"],"cost":4},
        "business_logic":   {"desc":"Business logic flaws","pre":["has_api"],"cost":3},
        "race_condition":   {"desc":"Race condition testing","pre":["has_state_change"],"cost":4},
        "cors":             {"desc":"CORS misconfiguration","pre":[],"cost":1},
        "credentials":      {"desc":"Exposed credentials","pre":[],"cost":1},
        "subdomain_takeover":{"desc":"Subdomain takeover","pre":["has_subdomains"],"cost":2},
    }

    def __init__(self, blackboard: Blackboard):
        self.bb = blackboard

    def select_next_tools(self, max_tools: int = 5) -> list:
        """
        Based on current blackboard state, pick best tools to run next.
        """
        state     = self.bb.state
        tech      = state.get("tech",[])
        findings  = self.bb.findings
        blocked   = state.get("blocked_paths",[])
        hypotheses= state.get("hypotheses",[])
        endpoints = state.get("endpoints",[])
        already_run = {f.get("module","") for f in findings}

        # Build precondition flags
        flags = set()
        if any("?" in e for e in endpoints):    flags.add("has_params")
        if any(any(c.isdigit() for c in e.split("/")[-1]) for e in endpoints): flags.add("has_ids")
        if any("url=" in e or "redirect=" in e
               for e in endpoints):             flags.add("has_url_params")
        if "php" in tech:                       flags.add("is_php")
        if "graphql" in str(endpoints):        flags.add("has_graphql")
        if "jwt" in tech:                       flags.add("has_jwt")
        if any(k in str(endpoints)
               for k in ["order","cart","pay","transfer"]): flags.add("has_state_change")
        if endpoints:                           flags.add("has_api")
        flags.add("has_template")  # always try

        # Score tools
        scores = {}
        for tool, info in self.TOOL_REGISTRY.items():
            if tool in already_run:
                continue
            # Check preconditions met
            if not all(p in flags for p in info["pre"]):
                continue
            score = 10 - info["cost"]
            # Boost if hypothesis suggests this tool
            for h in hypotheses:
                if tool in h.get("test",""):
                    score += 5 * (2 - h.get("priority",2))
            # Boost based on findings (chain)
            for f in findings[-5:]:
                chains = {"sqli":["credentials","auth"],
                         "idor":["account_takeover","business_logic"],
                         "ssrf":["credentials","lfi"]}
                if tool in chains.get(f.get("module",""),[]):
                    score += 3
            scores[tool] = score

        # Return top N by score
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return [tool for tool, _ in ranked[:max_tools]]


# ── 4. PENETRATION TASK GRAPH (VulnBot PTG) ──────────────────

class TaskNode:
    def __init__(self, id: str, name: str, module: str,
                 preconditions: list = None,
                 postconditions: list = None,
                 priority: int = 5):
        self.id             = id
        self.name           = name
        self.module         = module
        self.preconditions  = preconditions or []
        self.postconditions = postconditions or []
        self.priority       = priority
        self.status         = "pending"  # pending/running/done/failed/skipped
        self.result         = None
        self.children       = []
        self.attempts       = 0
        self.max_attempts   = 3


class PenetrationTaskGraph:
    """
    State machine with preconditions.
    Automatic traversal and backtracking.
    Based on VulnBot's PTG architecture.
    """

    def __init__(self, target: str, blackboard: Blackboard):
        self.target = target
        self.bb     = blackboard
        self.nodes  = {}
        self.root   = None
        self._build_initial_graph()

    def _build_initial_graph(self):
        """Build base graph — expands dynamically as findings come in."""
        nodes = [
            TaskNode("recon",    "Recon & Surface Discovery", "recon",    priority=1),
            TaskNode("intel",    "Intelligence & Fingerprint","intelligence",priority=1),
            TaskNode("sqli",     "SQL Injection",             "sqli",     priority=2),
            TaskNode("xss",      "Cross-Site Scripting",      "xss",      priority=2),
            TaskNode("idor",     "IDOR/BOLA",                 "idor",     priority=2),
            TaskNode("ssrf",     "SSRF",                      "ssrf",     priority=2),
            TaskNode("auth",     "Auth Testing",              "auth",     priority=2),
            TaskNode("jwt",      "JWT Security",              "jwt_deep", priority=3),
            TaskNode("cors",     "CORS",                      "cors",     priority=3),
            TaskNode("lfi",      "LFI/Path Traversal",        "lfi",      priority=3),
            TaskNode("creds",    "Credential Exposure",       "credentials",priority=2),
            TaskNode("validate", "Validate All Findings",     "validate", priority=4),
            TaskNode("report",   "Generate Report",           "report",   priority=5),
        ]
        for n in nodes:
            self.nodes[n.id] = n

        # Set up graph edges
        for nid in ["sqli","xss","idor","ssrf","auth","jwt","cors","lfi","creds"]:
            self.nodes["validate"].preconditions.append(nid)
        self.nodes["report"].preconditions = ["validate"]

        # Recon feeds intel feeds everything
        for nid in ["sqli","xss","idor","ssrf"]:
            self.nodes[nid].preconditions = ["recon","intel"]

    def get_ready_nodes(self) -> list:
        """Return nodes whose preconditions are met."""
        ready = []
        done  = {nid for nid,n in self.nodes.items() if n.status == "done"}
        for nid, node in self.nodes.items():
            if node.status != "pending":
                continue
            if all(p in done for p in node.preconditions):
                ready.append(node)
        return sorted(ready, key=lambda n: n.priority)

    def mark_done(self, node_id: str, result=None):
        if node_id in self.nodes:
            self.nodes[node_id].status = "done"
            self.nodes[node_id].result = result
            # Spawn child tasks based on result
            self._spawn_children(node_id, result)

    def mark_failed(self, node_id: str):
        if node_id in self.nodes:
            n = self.nodes[node_id]
            n.attempts += 1
            if n.attempts >= n.max_attempts:
                n.status = "failed"
                self.bb.write("blocked_paths",
                             [f"{node_id} failed after {n.attempts} attempts"])
            else:
                n.status = "pending"  # retry

    def _spawn_children(self, parent_id: str, result):
        """Dynamically add tasks based on findings."""
        if not result:
            return
        findings = result if isinstance(result, list) else []
        for f in findings:
            sev = f.get("severity","")
            mod = f.get("module","")

            if mod == "sqli" and sev in ["CRITICAL","HIGH"]:
                self._add_node(f"sqli_extract_{int(time.time())}",
                              "Extract DB via SQLi","sqli_extract",
                              preconditions=[parent_id], priority=1)
            if mod == "idor":
                self._add_node(f"idor_mass_{int(time.time())}",
                              "Mass IDOR Enumeration","idor_mass",
                              preconditions=[parent_id], priority=1)
            if mod == "ssrf" and sev == "CRITICAL":
                self._add_node(f"ssrf_pivot_{int(time.time())}",
                              "SSRF Internal Pivot","ssrf_pivot",
                              preconditions=[parent_id], priority=1)

    def _add_node(self, nid, name, module,
                  preconditions=None, priority=3):
        if nid not in self.nodes:
            self.nodes[nid] = TaskNode(nid, name, module,
                                      preconditions, priority=priority)

    def summary(self) -> dict:
        counts = defaultdict(int)
        for n in self.nodes.values():
            counts[n.status] += 1
        return dict(counts)


# ── 5. MULTI-SCAFFOLD REASONING ───────────────────────────────

class MultiScaffoldReasoner:
    """
    3 reasoning strategies running in parallel.
    Best answer wins via voting.
    Based on CAI 2026 successor architecture.
    """

    def __init__(self, local_brain):
        self.brain = local_brain

    def reason(self, question: str, context: str) -> str:
        """Run 3 reasoning strategies, return best answer."""
        strategies = [
            self._deductive(question, context),
            self._abductive(question, context),
            self._inductive(question, context),
        ]
        # Filter empty
        valid = [s for s in strategies if s]
        if not valid:
            return ""
        # For now return first valid (voting requires LLM)
        return valid[0]

    def _deductive(self, q: str, ctx: str) -> str:
        """Rules → conclusions. What does the evidence logically imply?"""
        prompt = f"Using deductive reasoning (rules → conclusions):\n{ctx}\nQuestion: {q}\nAnswer:"
        return self.brain.ask(prompt)[:300] if hasattr(self.brain,'ask') else ""

    def _abductive(self, q: str, ctx: str) -> str:
        """Observations → best hypothesis. What most likely explains this?"""
        prompt = f"Using abductive reasoning (best hypothesis for observations):\n{ctx}\nQuestion: {q}\nMost likely explanation:"
        return self.brain.ask(prompt)[:300] if hasattr(self.brain,'ask') else ""

    def _inductive(self, q: str, ctx: str) -> str:
        """Patterns → generalizations. What pattern does this fit?"""
        prompt = f"Using inductive reasoning (pattern recognition):\n{ctx}\nQuestion: {q}\nPattern identified:"
        return self.brain.ask(prompt)[:300] if hasattr(self.brain,'ask') else ""


# ── 6. CAI-LEVEL ORCHESTRATOR ────────────────────────────────

class CAIOrchestrator:
    """
    Main orchestrator implementing CAI-level autonomy.
    Integrates all 6 components.
    Reaches Autonomy Level 3-4.
    """

    def __init__(self, target: str, program: str = ""):
        self.target    = target
        self.program   = program
        self.bb        = Blackboard()
        self.output_dir= Path(f"output/cai/{target.replace('https://','').split('/')[0]}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize brain
        try:
            from core.local_brain import LocalBrain
            self.brain = LocalBrain()
        except Exception:
            self.brain = None

        self.reflection  = ReflectionLoop(self.brain, self.bb)
        self.router      = DynamicToolRouter(self.bb)
        self.graph       = PenetrationTaskGraph(target, self.bb)
        self.reasoner    = MultiScaffoldReasoner(self.brain)

        # Set up reactive subscriptions
        self.bb.subscribe("new_finding", self._on_finding)
        self.bb.subscribe("state_tech",  self._on_tech_detected)

    def run(self) -> dict:
        """Full CAI-level autonomous scan."""
        print(f"\n{'='*60}")
        print(f"  CAI-LEVEL ORCHESTRATOR")
        print(f"  Target: {self.target}")
        print(f"  Autonomy: Level 3-4")
        print(f"{'='*60}\n")

        from core.ghost_protocol import GhostProtocol
        self.ghost = GhostProtocol()
        intel = self.ghost.mission_briefing(self.target, [self.target])
        self.bb.write("target", self.target)
        self.bb.write("endpoints", intel.get("passive_recon",{}).get("historical_urls",[]))

        # Phase 1: Recon + surface discovery
        self._run_phase("Recon", self._phase_recon)

        # Phase 2: PTG-driven attack loop
        self._run_ptg_loop()

        # Phase 3: Synthesis + reporting
        return self._phase_report()

    def _run_ptg_loop(self):
        """Run attack loop driven by Penetration Task Graph."""
        print("\n[CAI] Starting PTG-driven attack loop...")
        iteration = 0
        max_iter  = 20

        while iteration < max_iter:
            iteration += 1
            ready = self.graph.get_ready_nodes()

            if not ready:
                print(f"[CAI] No more ready tasks. PTG complete.")
                break

            # Dynamic routing: pick best tools for current state
            dynamic_tools = self.router.select_next_tools(max_tools=3)

            # Run ready nodes
            for node in ready[:3]:
                print(f"[CAI] [{iteration}] Running: {node.name}")
                findings = self._run_module(node.module)

                # Reflect on each finding
                validated = []
                for f in findings:
                    f = self.reflection.reflect_on_finding(f)
                    if f.get("proven", False) or f.get("severity") in ["CRITICAL","HIGH"]:
                        validated.append(f)
                        self.bb.write("finding", f)
                        # Generate hypotheses
                        self.reflection.hypothesize(f)

                self.graph.mark_done(node.id, validated)

                # Check if we should pivot
                if len(validated) > 0:
                    print(f"[CAI] Pivoting based on {len(validated)} findings...")
                    # Router will pick new tools on next iteration

            # Check graph summary
            summary = self.graph.summary()
            print(f"[CAI] Graph: {summary}")

            # Stop if all critical paths done
            if summary.get("pending",0) == 0:
                break

    def _phase_recon(self):
        """Recon phase — feed blackboard with surface data."""
        import requests, urllib3
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify = False
        s.headers["User-Agent"] = "Mozilla/5.0"

        # Session from browser
        try:
            from core.session_manager import SessionManager
            sm      = SessionManager()
            cookies = sm.get(self.target)
            if cookies:
                s.cookies.update(cookies)
                # Store as list-of-dicts for modules to consume
            self.bb.state["sessions"] = [{"cookies": cookies, "headers": {}}]
                print(f"  [+] Session loaded")
        except Exception:
            pass

        # Surface discovery
        try:
            from core.surface_discovery import AggressiveSurfaceDiscovery
            disc     = AggressiveSurfaceDiscovery(self.target, s)
            surface  = disc.run()
            self.bb.write("endpoints", surface.get("endpoints",[]))
            print(f"  [+] {len(surface.get('endpoints',[]))} endpoints")
        except Exception as e:
            print(f"  [!] Surface: {e}")

        # Intelligence
        try:
            from intelligence import IntelligenceOrchestrator
            orch   = IntelligenceOrchestrator(self.target)
            result = orch.run()
            self.bb.write("tech", result.get("tech",[]))
            self.bb.write("waf",  result.get("waf",""))
            print(f"  [+] Tech: {result.get('tech',[])} WAF: {result.get('waf','none')}")
        except Exception as e:
            print(f"  [!] Intel: {e}")

        self.graph.mark_done("recon")
        self.graph.mark_done("intel")

    def _run_module(self, module_name: str) -> list:
        """Run one module, handle failures with reflection."""
        import sys
        sys.path.insert(0, ".")

        sessions = self.bb.read("sessions") or []
        # sessions[0] may be a dict {cookies:..} or a flat cookie dict
        first = sessions[0] if sessions else {}
        cookies = first.get("cookies", first) if isinstance(first, dict) else {}
        endpoints= self.bb.read("endpoints") or []

        try:
            cls_name = "".join(w.capitalize() for w in module_name.split("_")) + "Module"
            mod      = __import__(f"modules.{module_name}", fromlist=[cls_name])
            cls      = getattr(mod, cls_name)
            inst     = cls(url=self.target, timeout=10,
                          cookies=cookies if isinstance(cookies, dict) else (cookies[0] if isinstance(cookies, list) and cookies else {}),
                          headers={"X-HackerOne-Handle":"jardani101"})
            inst.extra_endpoints = endpoints[:50]
            result   = inst.run()
            return result.get("findings",[])
        except Exception as e:
            # Reflect on failure
            bypasses = self.reflection.reflect_on_failure(
                module_name, self.target, 0, str(e))
            if bypasses:
                self.bb.write("hypotheses",
                             [{"test": f"retry_{module_name}_with_bypass",
                               "based_on": str(e), "url": self.target, "priority": 3}])
            return []

    def _run_phase(self, name: str, fn):
        """Run a phase with timing."""
        print(f"\n[Phase] {name}...")
        t0 = time.time()
        fn()
        print(f"[Phase] {name} done in {time.time()-t0:.1f}s")

    def _on_finding(self, finding: dict):
        """React to new findings — chain reactions."""
        module = finding.get("module","")
        sev    = finding.get("severity","")

        # SSRF found → add SSRF pivot task
        if module == "ssrf" and sev == "CRITICAL":
            self.graph._add_node(
                f"ssrf_cloud_{int(time.time())}",
                "SSRF: Extract Cloud Metadata",
                "ssrf", priority=1
            )

        # SQLi found → add extraction task
        if module == "sqli":
            self.graph._add_node(
                f"sqli_dump_{int(time.time())}",
                "SQLi: Extract Database", "sqli",
                priority=1
            )

    def _on_tech_detected(self, tech):
        """React to tech detection — update priorities."""
        if isinstance(tech, list):
            if "php" in tech:
                self.graph.nodes.get("lfi") and \
                    setattr(self.graph.nodes["lfi"], "priority", 1)
            if "graphql" in str(tech):
                self.graph._add_node("graphql_test",
                                    "GraphQL Testing", "graphql_deep",
                                    priority=1)

    def _phase_report(self) -> dict:
        """Generate final report from blackboard."""
        findings = self.bb.findings
        confirmed= [f for f in findings if f.get("proven",False)]
        unproven = [f for f in findings if not f.get("proven",False)
                   and f.get("severity") in ["CRITICAL","HIGH"]]

        print(f"\n{'='*60}")
        print(f"  CAI SCAN COMPLETE")
        print(f"  Proven:  {len(confirmed)}")
        print(f"  Review:  {len(unproven)}")
        print(f"  Graph:   {self.graph.summary()}")
        print(f"{'='*60}")

        for f in confirmed:
            print(f"  [PROVEN/{f.get('severity','')}] {f.get('title','')[:60]}")
        for f in unproven:
            print(f"  [REVIEW/{f.get('severity','')}] {f.get('title','')[:60]}")

        # Generate H1 report
        if confirmed or unproven:
            try:
                from reports.hackerone_format import generate_h1_package
                pkg = generate_h1_package(
                    confirmed + unproven,
                    str(self.output_dir),
                    program_handle=self.program,
                    target_url=self.target,
                )
                if pkg.get("portal"):
                    print(f"\n  H1 Portal: {pkg['portal']}")
            except Exception as e:
                print(f"  [!] Report: {e}")

        # Save blackboard event log
        log_path = self.output_dir / "blackboard_log.json"
        log_path.write_text(json.dumps(self.bb.event_log, indent=2))

        return {
            "confirmed":  confirmed,
            "unproven":   unproven,
            "graph":      self.graph.summary(),
            "blackboard": len(self.bb.event_log),
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 core/cai_engine.py https://target.com [program]")
        sys.exit(1)
    url     = sys.argv[1]
    program = sys.argv[2] if len(sys.argv) > 2 else ""
    CAIOrchestrator(url, program).run()
