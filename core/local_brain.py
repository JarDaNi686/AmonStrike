"""
AmonStrike — Local Brain
Zero API. Zero internet. Runs entirely on your Kali machine.

Uses local LLM via Ollama (free, open source):
  Install: curl -fsSL https://ollama.ai/install.sh | sh
  Pull:    ollama pull llama3.2 (or mistral, codellama)
  Run:     ollama serve

Falls back to rule-based intelligence if no local model.
"""
import re, json, subprocess, shutil, requests
from pathlib import Path


OLLAMA_URL = "http://localhost:11434/api/generate"
MODELS     = ["llama3.2","mistral","codellama","llama3","phi3"]
MEMORY     = Path.home() / ".amonstrike" / "local_brain.json"


def _ollama_available() -> str:
    """Return model name if Ollama running, else empty string."""
    if not shutil.which("ollama"):
        return ""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models",[])]
            for preferred in MODELS:
                for m in models:
                    if preferred in m:
                        return m
            return models[0] if models else ""
    except Exception:
        return ""


def _ask_ollama(model: str, prompt: str) -> str:
    try:
        r = requests.post(OLLAMA_URL, json={
            "model":  model,
            "prompt": prompt,
            "stream": False,
        }, timeout=60)
        if r.status_code == 200:
            return r.json().get("response","")
    except Exception:
        pass
    return ""


class LocalBrain:
    """
    Local AI brain — no API needed.
    Uses Ollama + open source LLM if available.
    Falls back to rule engine if not.
    """

    def __init__(self):
        self.model  = _ollama_available()
        self.memory = self._load()
        if self.model:
            print(f"  [BRAIN] Local LLM: {self.model}")
        else:
            print("  [BRAIN] Rule-based mode (install Ollama for AI mode)")

    def ask(self, prompt: str) -> str:
        if self.model:
            return _ask_ollama(self.model, prompt)
        return ""

    def ask_json(self, prompt: str) -> dict:
        if self.model:
            reply = self.ask(prompt + "\n\nRespond with valid JSON only.")
            try:
                m = re.search(r'\{.*\}', reply, re.DOTALL)
                if m: return json.loads(m.group())
            except Exception:
                pass
        return {}

    # ── Rule-based fallbacks (always work, no model needed) ───

    def plan_attack(self, target: str, tech: list, purpose: str) -> dict:
        """Plan attack using local LLM or rule engine."""
        if self.model:
            result = self.ask_json(f"""
You are an expert penetration tester.
Target: {target}
Tech: {tech}
Purpose: {purpose}

Return JSON attack plan:
{{
  "priority_modules": ["module1","module2"],
  "skip_modules": ["module1"],
  "reasoning": "why",
  "high_value_endpoints": ["/api/users"]
}}""")
            if result: return result

        # Rule-based fallback
        priority = []
        skip     = ["headers","clickjacking","rate_limit","ssl_tls","cookies"]

        if any(db in tech for db in ["mysql","postgresql","mssql","sqlite"]):
            priority.insert(0, "sqli")
        if "php" in tech:
            priority.extend(["lfi","ssti","command_injection"])
        if "graphql" in tech:
            priority.extend(["graphql_deep","idor"])
        if "jwt" in tech:
            priority.extend(["jwt_deep","auth"])
        if purpose in ["ecommerce","fintech"]:
            priority.extend(["idor","business_logic","race_condition"])
        if purpose == "government":
            priority.extend(["ssrf","credentials","xxe","lfi"])

        for m in ["sqli","idor","ssrf","xss","cors","auth"]:
            if m not in priority: priority.append(m)

        return {"priority_modules": priority, "skip_modules": skip,
                "reasoning": "rule-based"}

    def validate_finding(self, finding: dict, response: str) -> dict:
        """Validate finding using local LLM or rule engine."""
        if self.model:
            result = self.ask_json(f"""
Finding: {json.dumps(finding, default=str)[:400]}
Response: {response[:300]}

Is this real or false positive? Return JSON:
{{"is_real": true, "confidence": 85, "reasoning": "why"}}""")
            if result: return result

        # Rule-based fallback
        evidence = finding.get("evidence","")
        module   = finding.get("module","")

        # SSRF: check response has real metadata
        if module == "ssrf":
            real = ["ami-id","instance-id","AccessKeyId","serviceAccounts"]
            is_real = any(k in evidence for k in real)
            return {"is_real": is_real, "confidence": 90 if is_real else 5,
                    "reasoning": "metadata check"}

        # RCE: check uid=N(name) pattern
        if module in ["command_injection","rce"]:
            def has_uid(text):
                if "uid=" not in text: return False
                idx = text.find("uid=")
                after = text[idx+4:idx+15]
                return any(c.isdigit() for c in after) and "(" in after
            is_real = has_uid(evidence) and not has_uid("")
            return {"is_real": is_real, "confidence": 95 if is_real else 5,
                    "reasoning": "uid pattern check"}

        # SQLi: real DB error
        if module == "sqli":
            db_errors = ["You have an error in your SQL","ORA-","pg_query",
                        "Microsoft SQL","sqlite3.OperationalError"]
            is_real = any(e in evidence for e in db_errors)
            return {"is_real": is_real, "confidence": 90 if is_real else 40,
                    "reasoning": "DB error pattern"}

        # XSS: payload in response
        if module == "xss":
            payload = str(finding.get("payload",""))
            is_real = payload and payload in evidence
            return {"is_real": is_real, "confidence": 80 if is_real else 20,
                    "reasoning": "payload reflection check"}

        return {"is_real": True, "confidence": 50, "reasoning": "unverified"}

    def chain_findings(self, findings: list) -> list:
        """Chain findings using local LLM or rule engine."""
        if self.model:
            result = self.ask_json(f"""
Findings: {json.dumps([{{'title':f.get('title',''),'module':f.get('module',''),'severity':f.get('severity','')}} for f in findings])}

Find vulnerability chains. Return JSON:
{{"chains": [{{"name": "chain", "findings": ["t1","t2"], "combined_severity": "CRITICAL", "bounty_estimate": 5000}}]}}""")
            if result: return result.get("chains",[])

        # Rule-based chains
        chains  = []
        modules = {f.get("module","") for f in findings}

        if "idor" in modules and "cors" in modules:
            chains.append({"name":"IDOR + CORS → ATO",
                          "combined_severity":"CRITICAL","bounty_estimate":5000})
        if "sqli" in modules and "auth" in modules:
            chains.append({"name":"SQLi + Auth Bypass → Full DB Access",
                          "combined_severity":"CRITICAL","bounty_estimate":8000})
        if "ssrf" in modules and "idor" in modules:
            chains.append({"name":"SSRF + IDOR → Internal Access",
                          "combined_severity":"CRITICAL","bounty_estimate":6000})
        if "xss" in modules and "csrf" in modules:
            chains.append({"name":"XSS + CSRF → ATO",
                          "combined_severity":"HIGH","bounty_estimate":2000})
        return chains

    def write_report(self, finding: dict, target: str) -> dict:
        """Write H1 report using local LLM or rule engine."""
        if self.model:
            result = self.ask_json(f"""
Write HackerOne bug report.
Target: {target}
Finding: {json.dumps(finding, default=str)[:500]}

Return JSON:
{{"title":"specific title","summary":"description","steps":["step1","step2"],"poc":"curl command","impact":"business impact","severity":"high"}}""")
            if result: return result

        # Rule-based fallback
        return {
            "title":    finding.get("title",""),
            "summary":  finding.get("description",""),
            "steps":    ["1. Navigate to target","2. Apply payload","3. Observe response"],
            "poc":      f"curl -sk \"{finding.get('url',target)}\"",
            "impact":   finding.get("impact","Security impact requires manual assessment"),
            "severity": finding.get("severity","medium").lower(),
        }

    def learn(self, findings: list, target: str, tech: list):
        mem = self._load()
        for f in findings:
            if f.get("severity") in ["CRITICAL","HIGH"]:
                mem.setdefault("patterns",[]).append({
                    "module": f.get("module",""),
                    "tech":   tech,
                    "target": target,
                })
        mem["patterns"] = mem["patterns"][-500:]
        MEMORY.parent.mkdir(parents=True, exist_ok=True)
        MEMORY.write_text(json.dumps(mem, indent=2, default=str))

    def _load(self) -> dict:
        try: return json.loads(MEMORY.read_text())
        except: return {"patterns":[]}


# Install helper
def install_ollama():
    print("""
To enable local AI brain on Kali:

1. Install Ollama:
   curl -fsSL https://ollama.ai/install.sh | sh

2. Pull a model (choose one):
   ollama pull llama3.2     # recommended — 2GB
   ollama pull mistral      # good for code — 4GB
   ollama pull codellama    # best for security — 4GB

3. Start Ollama:
   ollama serve

4. Run AmonStrike — brain auto-detects Ollama:
   sudo python3 run.py https://target.com
""")


if __name__ == "__main__":
    b = LocalBrain()
    if not b.model:
        install_ollama()
    else:
        print(f"Local brain ready: {b.model}")
        test = b.plan_attack("https://army.mil", ["php","mysql"], "government")
        print(f"Attack plan: {test}")
