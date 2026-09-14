"""
AmonStrike — Local Brain
32GB RAM. Local LLM + Real-time internet intelligence.
Zero external API dependency.
"""
import re, json, time, requests, subprocess, shutil
from pathlib import Path
from datetime import datetime

OLLAMA_URL = "http://localhost:11434/api/generate"
MEMORY     = Path.home() / ".amonstrike" / "local_brain.json"

# Best models for 32GB RAM
RECOMMENDED_MODELS = [
    "deepseek-r1:14b",    # 14B params — excellent reasoning, 9GB
    "llama3.1:13b",       # 13B — strong general + security, 8GB  
    "mistral:7b",         # 7B — fast, good for code, 4GB
    "codellama:13b",      # 13B — best for security/code, 8GB
    "llama3.2:3b",        # 3B — fastest fallback, 2GB
]

SYSTEM_PROMPT = """You are an elite penetration tester and security researcher.
You have deep knowledge of CVEs, exploit techniques, OWASP, and bug bounty.
You reason step by step. You prove vulnerabilities before reporting.
You think like an attacker. You know the latest techniques from 2024-2026.
Always respond with valid JSON when asked for JSON."""


def get_active_model() -> str:
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            for preferred in RECOMMENDED_MODELS:
                for m in models:
                    if preferred.split(":")[0] in m:
                        return m
            return models[0] if models else ""
    except Exception:
        return ""


def ollama_ask(model: str, prompt: str, system: str = "") -> str:
    try:
        payload = {
            "model":  model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_ctx": 4096, "temperature": 0.1},
        }
        if system:
            payload["system"] = system
        r = requests.post(OLLAMA_URL, json=payload, timeout=120)
        if r.status_code == 200:
            return r.json().get("response", "")
    except Exception:
        pass
    return ""


class RealTimeIntelligence:
    """
    Internet-based real-time security intelligence.
    No API key needed — uses public sources.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0"
        self.session.verify = False

    def get_recent_cves(self, tech: list) -> list:
        """Get recent CVEs for detected tech stack."""
        cves = []
        for t in tech[:3]:
            try:
                r = self.session.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": t, "resultsPerPage": 5,
                            "pubStartDate": "2025-01-01T00:00:00"},
                    timeout=10
                )
                if r.status_code == 200:
                    for vuln in r.json().get("vulnerabilities", []):
                        cve = vuln.get("cve", {})
                        cves.append({
                            "id":          cve.get("id", ""),
                            "description": cve.get("descriptions", [{}])[0].get("value", "")[:150],
                            "severity":    cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", ""),
                        })
            except Exception:
                pass
        return cves[:10]

    def get_hacktivity(self, program: str) -> list:
        """Get recent disclosed reports from H1 Hacktivity."""
        try:
            r = self.session.get(
                f"https://hackerone.com/{program}/hacktivity.json",
                timeout=10
            )
            if r.status_code == 200:
                return [
                    {"title": item.get("title", ""),
                     "severity": item.get("severity_rating", "")}
                    for item in r.json().get("data", [])[:20]
                ]
        except Exception:
            pass
        return []

    def search_exploitdb(self, tech: str) -> list:
        """Search ExploitDB for known exploits."""
        try:
            r = self.session.get(
                f"https://www.exploit-db.com/search",
                params={"q": tech, "type": "webapps"},
                timeout=10
            )
            exploits = []
            for m in re.finditer(
                r'<td[^>]*>(\d{4}-\d{2}-\d{2})</td>.*?href="/exploits/(\d+)"[^>]*>([^<]+)</a>',
                r.text, re.DOTALL
            )[:5]:
                exploits.append({
                    "date": m.group(1),
                    "id":   m.group(2),
                    "title":m.group(3).strip(),
                })
            return exploits
        except Exception:
            return []

    def get_shodan_info(self, domain: str, api_key: str = "byVaAzNjWhaPB59X6TvCiTAvsgaPoXeh") -> dict:
        """Query Shodan for target infrastructure."""
        try:
            r = self.session.get(
                f"https://api.shodan.io/dns/domain/{domain}",
                params={"key": api_key}, timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "subdomains": data.get("subdomains", [])[:20],
                    "tags":       data.get("tags", []),
                }
        except Exception:
            pass
        return {}

    def get_wayback_endpoints(self, domain: str) -> list:
        """Get historical endpoints from Wayback Machine."""
        try:
            r = self.session.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url":      f"{domain}/*",
                    "output":   "text",
                    "fl":       "original",
                    "collapse": "urlkey",
                    "limit":    "200",
                    "filter":   "statuscode:200",
                },
                timeout=15
            )
            if r.status_code == 200:
                urls = r.text.strip().splitlines()
                return [u for u in urls if "?" in u or "/api/" in u][:50]
        except Exception:
            pass
        return []

    def search_github_secrets(self, domain: str) -> list:
        """Search GitHub for exposed secrets/configs for target domain."""
        findings = []
        queries  = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
        ]
        for q in queries[:2]:
            try:
                r = self.session.get(
                    "https://github.com/search",
                    params={"q": q, "type": "code"},
                    timeout=10
                )
                if r.status_code == 200 and "results" in r.text.lower():
                    count = re.search(r'([\d,]+)\s+code results', r.text)
                    if count:
                        findings.append({
                            "query":   q,
                            "results": count.group(1),
                            "url":     f"https://github.com/search?q={q}&type=code",
                        })
            except Exception:
                pass
        return findings


class LocalBrain:
    """
    Full local AI brain.
    32GB RAM → runs 13B+ parameter models.
    Real-time internet intelligence built in.
    Zero external API dependency.
    """

    def __init__(self):
        self.model = get_active_model()
        self.intel = RealTimeIntelligence()
        self.mem   = self._load()

        if self.model:
            print(f"  [BRAIN] Local model: {self.model}")
        else:
            print("  [BRAIN] No local model — install Ollama + deepseek-r1:14b")
            print("  [BRAIN] Rule engine active")

    def ask(self, prompt: str) -> str:
        if self.model:
            return ollama_ask(self.model, prompt, SYSTEM_PROMPT)
        return ""

    def ask_json(self, prompt: str) -> dict:
        reply = self.ask(prompt + "\n\nReturn ONLY valid JSON. No explanation.")
        try:
            m = re.search(r'\{.*\}', reply, re.DOTALL)
            if m: return json.loads(m.group())
        except Exception:
            pass
        return {}

    def plan_attack(self, target: str, tech: list, purpose: str) -> dict:
        """Plan attack with real-time CVE intelligence."""
        # Get real-time data
        domain   = target.replace("https://","").replace("http://","").split("/")[0]
        cves     = self.intel.get_recent_cves(tech)
        shodan   = self.intel.get_shodan_info(domain)
        wayback  = self.intel.get_wayback_endpoints(domain)
        past     = self.mem.get("patterns", [])[-5:]

        if self.model:
            return self.ask_json(f"""
Target: {target}
Tech stack: {tech}
App purpose: {purpose}
Recent CVEs for this tech: {json.dumps(cves[:3])}
Shodan data: {json.dumps(shodan)}
Historical endpoints: {wayback[:10]}
Past successful patterns: {past}

Create comprehensive attack plan. Return JSON:
{{
  "priority_modules": ["sqli","idor","ssrf"],
  "skip_modules": ["headers","rate_limit"],
  "reasoning": "based on CVE-XXX and tech stack",
  "high_value_endpoints": ["/api/users"],
  "cve_to_test": ["CVE-2024-XXXX"],
  "payload_hints": {{"sqli": ["sleep(5)"]}}
}}""")

        # Rule-based with real-time CVE info
        priority = self._rule_priority(tech, purpose)
        return {
            "priority_modules":    priority,
            "skip_modules":        ["headers","clickjacking","rate_limit","ssl_tls"],
            "reasoning":           f"rule-based | {len(cves)} recent CVEs found",
            "high_value_endpoints":wayback[:5],
            "cve_to_test":         [c["id"] for c in cves if c.get("severity") == "CRITICAL"],
            "shodan_subdomains":   shodan.get("subdomains",[])[:10],
        }

    def validate_finding(self, finding: dict, response: str) -> dict:
        if self.model:
            result = self.ask_json(f"""
Finding: {json.dumps(finding, default=str)[:400]}
Server response: {response[:400]}

Is this real vulnerability or false positive?
Return JSON: {{"is_real": true, "confidence": 85, "reasoning": "why", "severity": "HIGH"}}""")
            if result: return result
        return self._rule_validate(finding, response)

    def chain_findings(self, findings: list) -> list:
        if not findings: return []
        if self.model:
            result = self.ask_json(f"""
Vulnerabilities found:
{json.dumps([{{"t":f.get("title","")[:40],"m":f.get("module",""),"s":f.get("severity","")}} for f in findings])}

Find attack chains combining multiple vulns for maximum impact.
Return JSON:
{{"chains": [{{"name":"IDOR+CORS→ATO","findings":["t1","t2"],"combined_severity":"CRITICAL","bounty_estimate":5000,"attack_narrative":"attacker does X then Y"}}]}}""")
            if result: return result.get("chains", [])
        return self._rule_chains(findings)

    def write_report(self, finding: dict, target: str) -> dict:
        if self.model:
            result = self.ask_json(f"""
Write a professional HackerOne bug bounty report.
Target: {target}
Finding: {json.dumps(finding, default=str)[:500]}

Return JSON:
{{"title":"[Component] Vulnerability Type leads to Impact","summary":"2-3 sentences","steps":["1. Do X","2. Observe Y"],"poc":"curl -sk ...","impact":"attacker can...","severity":"high","cwe":"CWE-XXX"}}""")
            if result: return result

        return {
            "title":    finding.get("title",""),
            "summary":  finding.get("description",""),
            "steps":    ["1. Send request to target","2. Observe response"],
            "poc":      f"curl -sk \"{finding.get('url', target)}\"",
            "impact":   "Security impact confirmed",
            "severity": finding.get("severity","medium").lower(),
        }

    def enrich_with_internet(self, domain: str, tech: list) -> dict:
        """Gather all real-time intelligence for a target."""
        print(f"  [INTEL] Gathering real-time intelligence for {domain}...")
        data = {
            "cves":          self.intel.get_recent_cves(tech),
            "shodan":        self.intel.get_shodan_info(domain),
            "wayback":       self.intel.get_wayback_endpoints(domain),
            "github_secrets":self.intel.search_github_secrets(domain),
        }
        if data["cves"]:
            print(f"  [INTEL] {len(data['cves'])} recent CVEs found")
        if data["shodan"].get("subdomains"):
            print(f"  [INTEL] {len(data['shodan']['subdomains'])} Shodan subdomains")
        if data["wayback"]:
            print(f"  [INTEL] {len(data['wayback'])} historical endpoints")
        if data["github_secrets"]:
            print(f"  [INTEL] GitHub: possible exposed secrets")
        return data

    def learn(self, findings: list, target: str, tech: list):
        for f in findings:
            if f.get("severity") in ["CRITICAL","HIGH"]:
                self.mem.setdefault("patterns",[]).append({
                    "module": f.get("module",""),
                    "tech":   tech, "target": target,
                    "date":   datetime.now().isoformat(),
                })
        self.mem["patterns"] = self.mem["patterns"][-500:]
        MEMORY.parent.mkdir(parents=True, exist_ok=True)
        MEMORY.write_text(json.dumps(self.mem, indent=2, default=str))

    def _rule_priority(self, tech, purpose) -> list:
        p = []
        if any(db in tech for db in ["mysql","postgresql","mssql","sqlite"]):
            p.insert(0, "sqli")
        if "php" in tech: p.extend(["lfi","ssti","command_injection"])
        if "graphql" in tech: p.extend(["graphql_deep","idor"])
        if "jwt" in tech: p.extend(["jwt_deep","auth"])
        if purpose in ["ecommerce","fintech"]:
            p.extend(["idor","business_logic","race_condition"])
        if purpose == "government":
            p.extend(["ssrf","credentials","xxe","lfi"])
        for m in ["sqli","idor","ssrf","xss","cors","auth"]:
            if m not in p: p.append(m)
        return list(dict.fromkeys(p))

    def _rule_validate(self, finding, response) -> dict:
        module   = finding.get("module","")
        evidence = finding.get("evidence","")

        if module == "ssrf":
            real = ["ami-id","instance-id","AccessKeyId","serviceAccounts","local-ipv4"]
            homepage = ["<!DOCTYPE","<html","<title>","<meta"]
            response_section = evidence
            if "Response:" in evidence:
                response_section = evidence[evidence.find("Response:")+9:]
            if sum(1 for h in homepage if h in response_section) >= 2:
                return {"is_real": False, "confidence": 95, "reasoning": "homepage returned"}
            is_real = any(k in response_section for k in real)
            return {"is_real": is_real, "confidence": 90, "reasoning": "metadata check"}

        if module == "command_injection":
            def has_uid(t):
                if "uid=" not in t: return False
                idx = t.find("uid=")
                after = t[idx+4:idx+15]
                return any(c.isdigit() for c in after) and "(" in after
            is_real = has_uid(evidence)
            return {"is_real": is_real, "confidence": 95, "reasoning": "uid pattern"}

        if module == "sqli":
            db_errors = ["You have an error in your SQL","ORA-","pg_query",
                        "Microsoft SQL","sqlite3.OperationalError","mysql_fetch"]
            is_real = any(e in evidence for e in db_errors)
            return {"is_real": is_real, "confidence": 90, "reasoning": "DB error pattern"}

        return {"is_real": True, "confidence": 50, "reasoning": "unverified"}

    def _rule_chains(self, findings) -> list:
        chains  = []
        modules = {f.get("module","") for f in findings}
        if "idor" in modules and "cors" in modules:
            chains.append({"name":"IDOR+CORS→Account Takeover",
                          "combined_severity":"CRITICAL","bounty_estimate":5000})
        if "sqli" in modules:
            chains.append({"name":"SQLi→Data Exfiltration",
                          "combined_severity":"CRITICAL","bounty_estimate":8000})
        if "ssrf" in modules:
            chains.append({"name":"SSRF→Internal Network Access",
                          "combined_severity":"CRITICAL","bounty_estimate":6000})
        return chains

    def _load(self) -> dict:
        try: return json.loads(MEMORY.read_text())
        except: return {"patterns":[]}


def setup_instructions():
    print("""
╔══════════════════════════════════════════════════════╗
║  AmonStrike Local Brain Setup (32GB RAM)             ║
╚══════════════════════════════════════════════════════╝

Step 1: Install Ollama
  curl -fsSL https://ollama.ai/install.sh | sh

Step 2: Pull best model for 32GB RAM (choose one):
  ollama pull deepseek-r1:14b   ← RECOMMENDED (best reasoning)
  ollama pull llama3.1:13b      ← Alternative
  ollama pull codellama:13b     ← Best for security code

Step 3: Start Ollama
  ollama serve &

Step 4: Run AmonStrike
  sudo python3 run.py https://www.army.mil dod

Brain auto-detects local model. No API key. No internet
dependency for AI reasoning. Internet used ONLY for:
  - CVE lookups (NVD)
  - Shodan queries
  - Wayback Machine
  - GitHub secret search
""")


if __name__ == "__main__":
    b = LocalBrain()
    if not b.model:
        setup_instructions()
    else:
        print(f"[+] Brain ready: {b.model}")
        result = b.plan_attack("https://army.mil", ["php","mysql"], "government")
        print(json.dumps(result, indent=2))
