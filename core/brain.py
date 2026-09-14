"""
AmonStrike — Claude Brain
Model: claude-sonnet-4-6
Full autonomous reasoning loop for penetration testing.
"""
import re, json, time, requests, urllib3
from datetime import datetime
from pathlib import Path

urllib3.disable_warnings()

MODEL      = "claude-sonnet-4-6"
API_URL    = "https://api.anthropic.com/v1/messages"
MEMORY     = Path.home() / ".amonstrike" / "brain.json"

SYSTEM = """You are an elite penetration tester with 20 years experience.
You reason about vulnerabilities, chain findings, and write precise H1 reports.
You think like an attacker. You prove everything before reporting.
You are part of AmonStrike — an autonomous security research tool.
Always respond with valid JSON when asked. Be specific, technical, accurate."""


class Brain:
    def __init__(self):
        self.history = []
        self.memory  = self._load()

    def ask(self, prompt: str) -> str:
        self.history.append({"role": "user", "content": prompt})
        try:
            r = requests.post(API_URL,
                headers={"Content-Type": "application/json"},
                json={
                    "model":      MODEL,
                    "max_tokens": 1000,
                    "system":     SYSTEM,
                    "messages":   self.history[-10:],
                },
                timeout=30)
            if r.status_code == 200:
                reply = r.json()["content"][0]["text"]
                self.history.append({"role": "assistant", "content": reply})
                return reply
        except Exception:
            pass
        return ""

    def ask_json(self, prompt: str) -> dict:
        reply = self.ask(prompt + "\n\nReturn ONLY valid JSON.")
        try:
            m = re.search(r'\{.*\}', reply, re.DOTALL)
            if m: return json.loads(m.group())
        except Exception:
            pass
        return {}

    # ── Core reasoning methods ─────────────────────────────────

    def plan_attack(self, target: str, tech: list, purpose: str) -> dict:
        return self.ask_json(f"""
Target: {target}
Tech stack: {tech}
App purpose: {purpose}
Past successful patterns: {self.memory.get('patterns', [])[:5]}

Create an attack plan. Return JSON:
{{
  "priority_modules": ["sqli","idor","ssrf"],
  "skip_modules": ["headers","rate_limit"],
  "reasoning": "why",
  "high_value_endpoints": ["/api/users","/api/orders"],
  "payload_hints": {{"sqli": ["payload1"]}}
}}""")

    def analyze_response(self, url: str, response_text: str,
                         status: int) -> dict:
        return self.ask_json(f"""
URL: {url} | Status: {status}
Response (first 500 chars): {response_text[:500]}

Analyze this response. Return JSON:
{{
  "interesting": true/false,
  "why": "reason",
  "vuln_indicators": ["sql error","debug info"],
  "next_test": "what to test next",
  "severity_hint": "CRITICAL/HIGH/MEDIUM/LOW/NONE"
}}""")

    def validate_finding(self, finding: dict, response: str) -> dict:
        return self.ask_json(f"""
Finding: {json.dumps(finding, default=str)[:400]}
Response evidence: {response[:400]}

Is this a real vulnerability or false positive? Return JSON:
{{
  "is_real": true/false,
  "confidence": 0-100,
  "reasoning": "why",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "needs_proof": "what evidence would confirm this"
}}""")

    def write_h1_report(self, finding: dict, target: str) -> dict:
        return self.ask_json(f"""
Write a HackerOne bug report for this finding.
Target: {target}
Finding: {json.dumps(finding, default=str)[:600]}

Return JSON:
{{
  "title": "specific title under 100 chars",
  "summary": "2-3 sentences",
  "steps": ["step 1","step 2","step 3"],
  "poc": "curl command or code",
  "impact": "business impact",
  "severity": "critical/high/medium/low",
  "cwe": "CWE-XXX"
}}""")

    def suggest_next(self, findings: list, tested: list,
                     remaining: list) -> dict:
        return self.ask_json(f"""
Scan progress:
Findings so far: {[f.get('title','')[:40] for f in findings[:5]]}
Modules tested: {tested[:10]}
Modules remaining: {remaining[:10]}

What should we do next? Return JSON:
{{
  "run_next": ["module1","module2"],
  "skip": ["module3"],
  "reasoning": "why",
  "priority_change": true/false
}}""")

    def chain_findings(self, findings: list) -> list:
        if not findings: return []
        result = self.ask_json(f"""
These vulnerabilities were found:
{json.dumps([{{'title':f.get('title',''),'severity':f.get('severity',''),'module':f.get('module','')}} for f in findings], indent=2)}

Identify vulnerability chains (combining multiple for higher impact).
Return JSON:
{{
  "chains": [
    {{
      "name": "chain name",
      "findings": ["title1","title2"],
      "combined_severity": "CRITICAL",
      "impact": "attacker can do X",
      "bounty_estimate": 5000
    }}
  ]
}}""")
        return result.get("chains", [])

    def learn(self, findings: list, target: str, tech: list):
        """Save what worked to memory."""
        mem = self._load()
        for f in findings:
            if f.get("severity") in ["CRITICAL","HIGH"]:
                mem.setdefault("patterns",[]).append({
                    "module":  f.get("module",""),
                    "tech":    tech,
                    "target":  target,
                    "date":    datetime.now().isoformat(),
                })
        mem["patterns"] = mem["patterns"][-200:]
        MEMORY.parent.mkdir(parents=True, exist_ok=True)
        MEMORY.write_text(json.dumps(mem, indent=2, default=str))

    def _load(self) -> dict:
        try: return json.loads(MEMORY.read_text())
        except: return {"patterns": []}
