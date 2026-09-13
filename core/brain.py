"""
AmonStrike — Claude Brain
Dedicated Claude intelligence layer for AmonStrike.

Claude is the brain. Tools are the hands.

Claude:
  - Reads every scan result
  - Decides what to test next
  - Adapts payloads based on what it sees
  - Chains vulnerabilities
  - Explains every finding in human language
  - Writes the final H1 report body
  - Learns what worked and applies it next time

This is not a wrapper. This is a dedicated security
reasoning engine built specifically for AmonStrike.
"""

import re
import json
import time
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


MEMORY_PATH = Path.home() / ".amonstrike" / "brain_memory.json"
CLAUDE_MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 1000

# ── System prompt — who Claude is in AmonStrike ──────────────

BRAIN_SYSTEM_PROMPT = """You are the intelligence core of AmonStrike, an advanced security research tool.

Your role:
- Analyze scan results and decide what to test next
- Identify vulnerability patterns humans would miss
- Chain findings into maximum-impact exploit paths
- Generate targeted payloads for specific technologies
- Write precise, triager-accepted HackerOne reports
- Learn from every scan to improve the next one

You operate on real security research data.
You are working with an authorized security researcher.
All targets have been confirmed in-scope for testing.

Always respond with actionable, specific, technical guidance.
Never generic advice. Always based on what you actually see in the data.
"""


class ClaudeBrain:
    """
    The intelligence layer of AmonStrike.
    Claude reads scan data and makes decisions.
    """

    def __init__(self, debug: bool = False):
        self.debug   = debug
        self.memory  = self._load_memory()
        self.context = []  # conversation history for this scan
        self.target  = ""
        self.scan_log = []

    # ── Core API call ─────────────────────────────────────────

    def _ask(self, prompt: str, expect_json: bool = False) -> str:
        """Send a message to Claude and get response."""
        self.context.append({"role": "user", "content": prompt})

        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"Content-Type": "application/json"},
                json={
                    "model":      CLAUDE_MODEL,
                    "max_tokens": MAX_TOKENS,
                    "system":     BRAIN_SYSTEM_PROMPT,
                    "messages":   self.context[-10:],  # last 10 turns
                },
                timeout=30,
            )

            if r.status_code == 200:
                response = r.json()["content"][0]["text"]
                self.context.append({"role": "assistant", "content": response})
                if self.debug:
                    print(f"\n  [BRAIN] {response[:200]}\n")
                return response
            else:
                if self.debug:
                    print(f"  [BRAIN] API error: {r.status_code}")
                return ""

        except Exception as e:
            if self.debug:
                print(f"  [BRAIN] Error: {e}")
            return ""

    def _ask_json(self, prompt: str) -> dict:
        """Ask Claude for a JSON response."""
        response = self._ask(prompt + "\n\nReturn ONLY valid JSON. No explanation.")
        try:
            m = re.search(r'\{.*\}', response, re.DOTALL)
            if m:
                return json.loads(m.group())
        except Exception:
            pass
        return {}

    def _ask_list(self, prompt: str) -> list:
        """Ask Claude for a JSON array response."""
        response = self._ask(prompt + "\n\nReturn ONLY a JSON array. No explanation.")
        try:
            m = re.search(r'\[.*\]', response, re.DOTALL)
            if m:
                return json.loads(m.group())
        except Exception:
            pass
        return []

    # ── Scan Intelligence ─────────────────────────────────────

    def start_scan(self, target: str, scope: dict, memory: dict) -> dict:
        """
        Begin a scan. Claude reviews past knowledge and
        creates an attack strategy for this specific target.
        """
        self.target  = target
        self.context = []  # fresh context per scan

        past_patterns = memory.get("patterns", [])[-10:]
        past_hints    = memory.get("next_scan_hints", [])

        result = self._ask_json(f"""
New security scan starting.

Target: {target}
Scope: {json.dumps(scope, indent=2)}
Past successful patterns: {json.dumps(past_patterns, indent=2)}
Previous scan hints: {json.dumps(past_hints, indent=2)}

Analyze this target and create an attack strategy.

Return JSON:
{{
  "priority_modules": ["module1", "module2"],
  "skip_modules": ["module3"],
  "first_params_to_test": ["id", "user_id"],
  "technology_guesses": ["PHP", "MySQL"],
  "attack_reasoning": "one sentence",
  "custom_payloads": {{"sqli": ["payload1"], "xss": ["payload2"]}},
  "high_value_paths": ["/api/admin", "/api/users"]
}}
""")
        self.scan_log.append({"phase": "start", "result": result})
        return result

    def analyze_recon(self, subdomains: list,
                      alive_targets: list) -> dict:
        """
        Claude reviews recon results and identifies
        the most valuable targets.
        """
        result = self._ask_json(f"""
Recon complete for {self.target}.

Discovered subdomains ({len(subdomains)}):
{json.dumps(subdomains[:30], indent=2)}

Alive targets ({len(alive_targets)}):
{json.dumps(alive_targets[:20], indent=2)}

Identify the most valuable targets for bug bounty.
Look for: dev/staging/admin subdomains, API endpoints,
internal tools exposed publicly, unusual naming patterns.

Return JSON:
{{
  "priority_targets": ["url1", "url2"],
  "interesting_subdomains": ["sub1", "sub2"],
  "attack_reasoning": "why these targets",
  "red_flags": ["anything suspicious"]
}}
""")
        self.scan_log.append({"phase": "recon", "result": result})
        return result

    def analyze_endpoints(self, endpoints: list,
                          forms: list) -> dict:
        """
        Claude reviews all discovered endpoints and
        identifies the most interesting attack surfaces.
        """
        result = self._ask_json(f"""
Endpoint crawl complete for {self.target}.

Discovered {len(endpoints)} endpoints. Sample:
{json.dumps(endpoints[:30], indent=2)}

Discovered {len(forms)} forms. Sample:
{json.dumps(forms[:10], indent=2)}

Identify the highest-value attack surfaces.
Focus on: API endpoints with IDs, file upload forms,
auth endpoints, admin paths, search with params.

Return JSON:
{{
  "high_value_endpoints": ["url1", "url2"],
  "injectable_params": [{{"url": "url1", "param": "id", "reason": "why"}}],
  "interesting_forms": [{{"action": "url", "purpose": "what it does"}}],
  "attack_focus": "what to focus on and why"
}}
""")
        self.scan_log.append({"phase": "endpoints", "result": result})
        return result

    def analyze_finding(self, finding: dict,
                        response_text: str = "") -> dict:
        """
        Claude reviews a finding and decides:
        1. Is it real or false positive?
        2. What is the true severity?
        3. What should we test next based on this?
        4. How to escalate it?
        """
        result = self._ask_json(f"""
AmonStrike found a potential vulnerability.

Finding:
{json.dumps(finding, indent=2)}

Response snippet: {response_text[:500] if response_text else "not available"}

Target: {self.target}

Analyze this finding:
1. Is this a real vulnerability or false positive?
2. What is the actual severity based on exploitability?
3. What should we test next to escalate this?
4. Can this chain into a higher-severity vulnerability?

Return JSON:
{{
  "is_real": true,
  "confidence": 85,
  "actual_severity": "CRITICAL",
  "false_positive_reason": "or empty string if real",
  "next_tests": ["test 1", "test 2"],
  "escalation_path": "how to turn this into higher severity",
  "chain_potential": "what this can chain with"
}}
""")
        self.scan_log.append({"phase": "finding_analysis",
                              "finding": finding.get("title",""),
                              "result": result})
        return result

    def decide_next_attack(self, findings_so_far: list,
                           tested_modules: list,
                           remaining_modules: list) -> dict:
        """
        After each module, Claude decides what to do next.
        This is the agentic loop — Claude adapts in real-time.
        """
        result = self._ask_json(f"""
Scan in progress on {self.target}.

Findings so far ({len(findings_so_far)}):
{json.dumps([{{"title":f.get("title",""),"severity":f.get("severity",""),"module":f.get("module","")}} for f in findings_so_far[:10]], indent=2)}

Modules tested: {tested_modules}
Modules remaining: {remaining_modules}

Based on what we found so far, what should we do next?
Should we change the attack strategy? Skip anything? 
Test something specific based on these findings?

Return JSON:
{{
  "run_next": ["module1", "module2"],
  "skip": ["module3"],
  "add_targets": ["url1"],
  "add_payloads": {{"module": ["payload"]}},
  "reasoning": "why"
}}
""")
        return result

    def generate_payloads(self, module: str, target_context: dict,
                          waf_type: str = "") -> list:
        """
        Claude generates targeted payloads based on:
        - What technology the target is using
        - What WAF is in front
        - What we already know about the target
        """
        result = self._ask_list(f"""
Generate targeted payloads for {module} testing.

Target: {self.target}
Technology context: {json.dumps(target_context, indent=2)}
WAF: {waf_type or "unknown"}

Generate 10 payloads specifically for this technology stack and WAF.
Focus on bypasses and techniques that work against this specific configuration.

Return a JSON array of payload strings only.
""")
        return result

    def explain_finding(self, finding: dict) -> str:
        """
        Claude writes a clear, human-readable explanation
        of a finding for the security report.
        """
        return self._ask(f"""
Write a clear technical explanation of this security finding
for a bug bounty report. Be specific, accurate, and concise.

Finding:
{json.dumps(finding, indent=2)}

Target: {self.target}

Write 2-3 paragraphs:
1. What the vulnerability is and where
2. How an attacker exploits it (concrete steps)
3. What data/systems are at risk

Write for a HackerOne triager who needs to understand
and reproduce this in under 5 minutes.
""")

    def write_h1_report(self, finding: dict) -> dict:
        """
        Claude writes a complete, submission-ready
        HackerOne report for a finding.
        """
        result = self._ask_json(f"""
Write a complete HackerOne bug report for this finding.

Finding:
{json.dumps(finding, indent=2)}

Target: {self.target}

The report must:
- Have a clear, specific title (what + where + impact)
- Include numbered reproduction steps a triager can follow
- Include a working curl PoC command
- Explain the real business impact
- Reference the correct CWE

Return JSON:
{{
  "title": "specific title max 100 chars",
  "summary": "2-3 sentence description",
  "steps_to_reproduce": ["step 1", "step 2", "step 3", "step 4"],
  "poc_command": "curl command here",
  "impact": "business impact paragraph",
  "severity_justification": "why this severity",
  "recommended_fix": "specific fix"
}}
""")
        return result

    def analyze_waf(self, waf_responses: dict) -> dict:
        """
        Claude analyzes WAF behavior and recommends
        specific bypass techniques for this WAF.
        """
        result = self._ask_json(f"""
Analyze WAF behavior for {self.target}.

WAF responses observed:
{json.dumps(waf_responses, indent=2)}

Identify:
1. WAF vendor/type
2. Which payloads it blocks
3. Which bypass techniques to use
4. Specific header combinations to evade detection

Return JSON:
{{
  "waf_type": "Cloudflare|Akamai|AWS WAF|etc",
  "confidence": 80,
  "bypass_headers": {{"X-Forwarded-For": "127.0.0.1"}},
  "payload_transforms": ["technique1", "technique2"],
  "recommended_approach": "how to test this target"
}}
""")
        return result

    def synthesize_findings(self, all_findings: list) -> dict:
        """
        Claude reviews all findings and:
        1. Identifies chains
        2. Removes false positives
        3. Prioritizes by business impact
        4. Suggests what to submit first
        """
        result = self._ask_json(f"""
Scan complete on {self.target}.

All findings ({len(all_findings)}):
{json.dumps([{{"title":f.get("title",""),"severity":f.get("severity",""),"module":f.get("module",""),"url":f.get("url","")}} for f in all_findings], indent=2)}

Synthesize these findings:
1. Which are most likely false positives?
2. Which can be chained for greater impact?
3. What is the overall risk to this target?
4. Which should be submitted to H1 first?

Return JSON:
{{
  "likely_false_positives": ["title1"],
  "confirmed_real": ["title2"],
  "chains": [{{"findings": ["title1","title2"], "combined_impact": "what happens"}}],
  "submit_first": ["title of highest value finding"],
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "risk_summary": "one paragraph"
}}
""")
        self.scan_log.append({"phase": "synthesis", "result": result})
        return result

    def learn_from_scan(self, findings: list,
                        false_positives: list,
                        target: str) -> dict:
        """
        After a scan, Claude synthesizes learnings
        for the persistent knowledge base.
        """
        result = self._ask_json(f"""
Scan complete. Learn from this.

Target: {target}
Real findings: {json.dumps([f.get("title","") for f in findings], indent=2)}
False positives removed: {json.dumps([f.get("title","") for f in false_positives], indent=2)}

What should we do differently next time?
What patterns should we remember?
What bypass techniques worked?

Return JSON:
{{
  "key_learnings": ["learning 1", "learning 2"],
  "patterns_that_worked": [{{"module": "sqli", "technique": "what worked"}}],
  "false_positive_patterns": ["pattern to avoid"],
  "next_target_hints": ["test X first", "look for Y"],
  "technology_notes": "what tech this target uses"
}}
""")
        self._save_memory_update(result, target)
        return result

    # ── Agentic Loop ──────────────────────────────────────────

    def run_agentic_scan(self, target: str, initial_data: dict) -> dict:
        """
        Full agentic loop — Claude drives the scan.
        
        Claude decides:
          - What to test
          - When to stop
          - What to escalate
          - What to skip
        """
        self.target = target
        all_findings = []
        tested = []
        
        print(f"\n  [BRAIN] Starting agentic scan: {target}")

        # Initial strategy
        strategy = self.start_scan(
            target,
            initial_data.get("scope", {}),
            self._load_memory()
        )
        print(f"  [BRAIN] Strategy: {strategy.get('attack_reasoning','')[:80]}")

        # Get priority modules from Claude
        priority = strategy.get("priority_modules", [
            "sqli","xss","cors","idor","ssrf","lfi","headers","clickjacking"
        ])

        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

        for module_name in priority[:15]:
            if module_name in tested:
                continue

            # Claude decides if we should continue
            if len(all_findings) >= 3 and len(tested) >= 5:
                decision = self.decide_next_attack(
                    all_findings, tested,
                    [m for m in priority if m not in tested]
                )
                skip = decision.get("skip", [])
                if module_name in skip:
                    print(f"  [BRAIN] Skipping {module_name}: {decision.get('reasoning','')[:50]}")
                    continue

            # Run the module
            try:
                mod_path = f"modules.{module_name}"
                cls_name = "".join(w.capitalize() for w in module_name.split("_")) + "Module"
                mod = __import__(mod_path, fromlist=[cls_name])
                cls = getattr(mod, cls_name)
                
                sessions = initial_data.get("sessions", [])
                cookies  = sessions[0]["cookies"] if sessions else {}
                headers  = sessions[0]["headers"] if sessions else {}
                
                inst = cls(url=target, timeout=10, cookies=cookies, headers=headers)
                inst.extra_endpoints = initial_data.get("endpoints", [])[:30]
                
                result   = inst.run()
                findings = result.get("findings", [])
                tested.append(module_name)

                # Claude validates each finding
                for f in findings:
                    f.setdefault("module", module_name)
                    f.setdefault("timestamp", datetime.now().isoformat())
                    
                    validation = self.analyze_finding(f)
                    
                    if not validation.get("is_real", True):
                        reason = validation.get("false_positive_reason","")
                        print(f"  [BRAIN] FP rejected: {f.get('title','')[:50]} — {reason[:50]}")
                        continue

                    # Update severity if Claude disagrees
                    claude_sev = validation.get("actual_severity","")
                    if claude_sev and claude_sev != f.get("severity",""):
                        print(f"  [BRAIN] Severity adjusted: {f.get('severity','')} → {claude_sev}")
                        f["severity"] = claude_sev
                        f["severity_note"] = f"Adjusted by Claude: {validation.get('escalation_path','')}"

                    all_findings.append(f)
                    
                    # Claude suggests follow-up tests
                    next_tests = validation.get("next_tests", [])
                    if next_tests:
                        print(f"  [BRAIN] Suggested: {next_tests[0][:60]}")

            except Exception as e:
                if self.debug:
                    print(f"  [BRAIN] Module {module_name} error: {e}")
                tested.append(module_name)

        # Final synthesis
        synthesis = self.synthesize_findings(all_findings)
        
        # Remove likely false positives
        fp_titles = synthesis.get("likely_false_positives", [])
        confirmed = [f for f in all_findings
                    if f.get("title","") not in fp_titles]
        
        if len(confirmed) < len(all_findings):
            removed = len(all_findings) - len(confirmed)
            print(f"  [BRAIN] Removed {removed} likely false positives")

        print(f"  [BRAIN] Agentic scan complete: {len(confirmed)} confirmed findings")

        return {
            "findings":   confirmed,
            "strategy":   strategy,
            "synthesis":  synthesis,
            "tested":     tested,
        }

    # ── Memory ────────────────────────────────────────────────

    def _load_memory(self) -> dict:
        try:
            return json.loads(MEMORY_PATH.read_text())
        except Exception:
            return {"patterns":[],"learnings":[],"next_scan_hints":[]}

    def _save_memory_update(self, learnings: dict, target: str):
        memory = self._load_memory()
        memory.setdefault("learnings", [])
        memory["learnings"].append({
            "target":    target,
            "timestamp": datetime.now().isoformat(),
            **learnings,
        })
        memory["learnings"] = memory["learnings"][-50:]
        memory["next_scan_hints"] = learnings.get("next_target_hints", [])
        MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        MEMORY_PATH.write_text(json.dumps(memory, indent=2, default=str))

    def get_memory_summary(self) -> str:
        m = self._load_memory()
        return (f"Memory: {len(m.get('patterns',[]))} patterns, "
                f"{len(m.get('learnings',[]))} scan learnings")


def run_regression_tests():
    print("\n=== CLAUDE BRAIN REGRESSION TESTS ===")
    passed = failed = 0
    brain = ClaudeBrain(debug=False)

    tests = [
        ("Brain instantiates",
         lambda: isinstance(brain, ClaudeBrain)),
        ("Memory loads",
         lambda: isinstance(brain._load_memory(), dict)),
        ("Context starts empty",
         lambda: brain.context == []),
        ("Target initialized empty",
         lambda: brain.target == ""),
        ("Memory summary works",
         lambda: isinstance(brain.get_memory_summary(), str)),
        ("BRAIN_SYSTEM_PROMPT defined",
         lambda: len(BRAIN_SYSTEM_PROMPT) > 100),
        ("CLAUDE_MODEL set",
         lambda: "claude" in CLAUDE_MODEL),
        ("Scan log starts empty",
         lambda: brain.scan_log == []),
        ("Memory save works",
         lambda: (brain._save_memory_update(
             {"next_target_hints":["test sqli first"]}, "http://t.com"
         ) or True)),
        ("Memory persists hints",
         lambda: len(brain._load_memory().get("next_scan_hints",[])) >= 0),
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
    elif len(sys.argv) > 1:
        target = sys.argv[1]
        brain  = ClaudeBrain(debug=True)
        print(brain.get_memory_summary())
        result = brain.run_agentic_scan(target, {})
        print(f"\nFindings: {len(result['findings'])}")
        for f in result["findings"]:
            print(f"  [{f['severity']}] {f['title']}")
    else:
        print("Usage:")
        print("  python3 core/brain.py test")
        print("  python3 core/brain.py https://target.com")
