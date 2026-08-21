"""
AmonStrike — AutomateEngine
Eliminates the manual deep dive completely.

What a human researcher does in 4-6 hours manually,
this does in 10-15 minutes automatically:

  1. AUTO-REGISTER: Create userA + userB from scratch
  2. AUTHENTICATED CRAWL: Browse entire app as userA
  3. REQUEST CAPTURE: Record every HTTP request made
  4. SESSION REPLAY: Replay every request as userB + unauthenticated
  5. DIFF ANALYSIS: Compare responses — find IDOR/access control bugs
  6. PARAMETER INJECTION: Add hidden fields to every form
  7. ID MANIPULATION: Test adjacent IDs on every object reference

This is the Autorize technique — automated and extended.
"""

import re
import json
import time
import uuid
import random
import string
import hashlib
import asyncio
import requests
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import List, Dict, Optional, Set, Tuple
from difflib import SequenceMatcher


# ── Temp Email for Auto-Registration ─────────────────────────

class TempMailClient:
    """Generate disposable emails for auto-registration."""

    PROVIDERS = [
        "guerrillamail.com",
        "mailinator.com",
        "yopmail.com",
        "tempmail.org",
    ]

    def __init__(self):
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "Mozilla/5.0"

    def create(self) -> dict:
        """Create a temporary email address."""
        # Generate a random username
        username = "amonstrike_" + "".join(
            random.choices(string.ascii_lowercase + string.digits, k=10)
        )

        # Try Guerrilla Mail API
        try:
            r = self._session.get(
                "https://api.guerrillamail.com/ajax.php",
                params={"f": "get_email_address", "ip": "127.0.0.1",
                        "agent": "Mozilla"},
                timeout=10
            )
            if r.status_code == 200:
                data    = r.json()
                email   = data.get("email_addr", "")
                sid_tok = data.get("sid_token", "")
                if email:
                    return {
                        "email":    email,
                        "username": email.split("@")[0],
                        "provider": "guerrillamail",
                        "sid_token":sid_tok,
                    }
        except Exception:
            pass

        # Fallback: mailinator (no API needed, just use the address)
        email = f"{username}@mailinator.com"
        return {
            "email":    email,
            "username": username,
            "provider": "mailinator",
            "sid_token":"",
        }

    def get_verification_link(self, email_info: dict, wait: int = 30) -> Optional[str]:
        """Wait for and extract verification link from inbox."""
        if email_info.get("provider") != "guerrillamail":
            return None
        sid = email_info.get("sid_token", "")
        seq = 0
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                r = self._session.get(
                    "https://api.guerrillamail.com/ajax.php",
                    params={"f":"check_email","seq":seq,"sid_token":sid},
                    timeout=10
                )
                if r.status_code == 200:
                    emails = r.json().get("list", [])
                    for mail in emails:
                        body = mail.get("mail_body", "")
                        link = re.search(r'https?://[^\s"\'<>]+verify[^\s"\'<>]*', body)
                        if link:
                            return link.group()
                        link = re.search(r'https?://[^\s"\'<>]+confirm[^\s"\'<>]*', body)
                        if link:
                            return link.group()
            except Exception:
                pass
            time.sleep(3)
        return None


# ── Auto-Registration Engine ──────────────────────────────────

class AutoRegistrar:
    """
    Automatically creates user accounts on the target application.
    Supports: JSON API, HTML forms, email verification.
    """

    REGISTER_PATHS = [
        "/api/register", "/api/signup", "/api/users", "/api/auth/register",
        "/api/v1/register", "/api/v1/users", "/api/v1/signup",
        "/register", "/signup", "/join", "/create-account",
        "/api/v2/register", "/api/auth/signup",
    ]

    def __init__(self, base_url: str, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = "Mozilla/5.0"
        self._temp_mail = TempMailClient()
        self.created_accounts: List[Dict] = []

    def create_account(self, role: str = "user",
                       username_prefix: str = "amonstrike") -> Optional[Dict]:
        """
        Create a new account on the target.
        Returns account info dict or None if registration failed.
        """
        email_info = self._temp_mail.create()
        suffix     = "".join(random.choices(string.digits, k=6))
        username   = f"{username_prefix}_{suffix}"
        password   = f"AmonStr1ke!{suffix}@#"

        account = {
            "username": username,
            "email":    email_info["email"],
            "password": password,
            "role":     role,
            "registered_at": datetime.now().isoformat(),
            "verified":      False,
        }

        # Try API registration first
        if self._try_api_register(account):
            print(f"  [+] Auto-registered ({role}): {account['email']}")
            self.created_accounts.append(account)
            return account

        # Try HTML form registration
        if self._try_form_register(account):
            print(f"  [+] Auto-registered via form ({role}): {account['email']}")
            self.created_accounts.append(account)
            return account

        print(f"  [~] Auto-registration failed — use --credentials instead")
        return None

    def _try_api_register(self, account: dict) -> bool:
        """Try registering via JSON API."""
        payloads = [
            {"username": account["username"], "email": account["email"],
             "password": account["password"], "password_confirmation": account["password"]},
            {"email": account["email"], "password": account["password"],
             "name": account["username"]},
            {"user": {"email": account["email"], "password": account["password"],
                      "username": account["username"]}},
        ]
        for path in self.REGISTER_PATHS:
            url = self.base_url + path
            try:
                r = self.session.head(url, timeout=5)
                if r.status_code == 404:
                    continue
            except Exception:
                continue

            for payload in payloads:
                try:
                    r = self.session.post(url, json=payload, timeout=self.timeout)
                    if r.status_code in [200, 201]:
                        # Check if we got a token (success)
                        try:
                            data = r.json()
                            for field in ["token","access_token","user","id","email"]:
                                if field in str(data):
                                    account["register_url"] = url
                                    account["register_method"] = "api_json"
                                    # Try to extract user ID
                                    for id_field in ["id","user_id","_id","uid"]:
                                        if id_field in data:
                                            account["user_id"] = str(data[id_field])
                                    return True
                        except Exception:
                            if r.status_code == 201:
                                account["register_url"] = url
                                account["register_method"] = "api_json"
                                return True
                except Exception:
                    continue
        return False

    def _try_form_register(self, account: dict) -> bool:
        """Find and submit HTML registration form."""
        for path in ["/register", "/signup", "/join", "/"]:
            try:
                r = self.session.get(self.base_url + path, timeout=self.timeout)
                if r.status_code != 200:
                    continue

                forms = self._extract_register_forms(r.text, r.url)
                for form in forms:
                    data = dict(form.get("inputs", {}))
                    # Fill fields
                    for f in ["username","name","login"]:
                        if f in data: data[f] = account["username"]
                    for f in ["email","mail","email_address"]:
                        if f in data: data[f] = account["email"]
                    for f in ["password","passwd","pass","pwd"]:
                        if f in data: data[f] = account["password"]
                    for f in ["password_confirmation","password2","confirm_password","retype"]:
                        if f in data: data[f] = account["password"]

                    action = form.get("action","")
                    if not action.startswith("http"):
                        action = urljoin(r.url, action)

                    r2 = self.session.post(action, data=data,
                                           timeout=self.timeout, allow_redirects=True)
                    if r2.status_code in [200, 201, 302]:
                        # Not same page = success
                        if r2.url != r.url or "success" in r2.text.lower() or \
                           "welcome" in r2.text.lower() or "verify" in r2.text.lower():
                            account["register_url"]    = action
                            account["register_method"] = "html_form"
                            return True
            except Exception:
                continue
        return False

    def _extract_register_forms(self, html: str, base_url: str) -> list:
        forms = []
        for m in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.DOTALL | re.I):
            attrs   = m.group(1)
            content = m.group(2)
            action  = re.search(r'action=["\']([^"\']+)', attrs)
            method  = re.search(r'method=["\']([^"\']+)', attrs, re.I)
            inputs  = {}
            for inp in re.finditer(r'<input([^>]+)>', content, re.I):
                name  = re.search(r'name=["\']([^"\']+)', inp.group(1))
                value = re.search(r'value=["\']([^"\']*)', inp.group(1))
                if name:
                    inputs[name.group(1)] = value.group(1) if value else ""

            has_email = any(f in inputs for f in ["email","mail"])
            has_pass  = any(f in inputs for f in ["password","passwd"])
            is_reg    = has_email and has_pass and len(inputs) >= 3

            if is_reg:
                forms.append({
                    "action":   action.group(1) if action else "",
                    "method":   method.group(1).lower() if method else "post",
                    "inputs":   inputs,
                })
        return forms


# ── Authenticated Crawler ─────────────────────────────────────

class AuthenticatedCrawler:
    """
    Crawls the entire application as a logged-in user.
    Records every HTTP request made during crawling.
    Uses Playwright for JavaScript-rendered content.
    """

    def __init__(self, base_url: str, session_cookies: dict = None,
                 auth_headers: dict = None, max_pages: int = 100,
                 timeout: int = 30):
        self.base_url      = base_url.rstrip("/")
        self.parsed        = urlparse(base_url)
        self.domain        = self.parsed.hostname or ""
        self.session_cookies = session_cookies or {}
        self.auth_headers  = auth_headers or {}
        self.max_pages     = max_pages
        self.timeout       = timeout
        self.captured_requests: List[Dict] = []
        self.visited_urls:  Set[str] = set()
        self.forms_found:   List[Dict] = []
        self._lock         = threading.Lock()

    def crawl(self) -> List[Dict]:
        """
        Crawl the application and capture all requests.
        Returns list of captured request records.
        """
        print(f"\n  [*] Authenticated crawl starting: {self.base_url}")
        print(f"      Max pages: {self.max_pages}")

        # Try Playwright first (handles JS) — skip if chromium not installed
        try:
            from playwright.sync_api import sync_playwright as _sp
            import shutil as _sh
            # Check if chromium binary actually exists before trying
            _test = _sp()
            _b = _test.__enter__()
            _browser_path = _b.chromium.executable_path
            _test.__exit__(None, None, None)
            if not _sh.os.path.exists(_browser_path):
                raise FileNotFoundError(f"Chromium not found at {_browser_path}")
            captured = self._crawl_playwright()
            if captured:
                print(f"  [+] Playwright crawl: {len(captured)} requests captured")
                return captured
        except FileNotFoundError as e:
            print(f"  [~] Chromium not installed — fix: sudo playwright install chromium")
            print(f"  [~] Falling back to requests crawler")
        except Exception as e:
            print(f"  [~] Playwright unavailable ({type(e).__name__}) — using requests crawler")

        # Fallback: requests-based crawler
        captured = self._crawl_requests()
        print(f"  [+] Requests crawl: {len(captured)} requests captured")
        return captured

    def _crawl_playwright(self) -> List[Dict]:
        """Playwright-based crawl — handles SPAs and JS-rendered content."""
        from playwright.sync_api import sync_playwright
        captured = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx     = browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=self.auth_headers,
            )
            # Set cookies
            if self.session_cookies:
                cookies = [
                    {"name": k, "value": v, "domain": self.domain,
                     "path": "/", "sameSite": "None"}
                    for k, v in self.session_cookies.items()
                ]
                ctx.add_cookies(cookies)

            page    = ctx.new_page()
            visited = set()
            queue   = [self.base_url]

            def on_request(request):
                if self.domain in request.url:
                    with self._lock:
                        captured.append({
                            "method":   request.method,
                            "url":      request.url,
                            "headers":  dict(request.headers),
                            "post_data":request.post_data or "",
                            "timestamp":datetime.now().isoformat(),
                            "source":   "playwright",
                        })

            page.on("request", on_request)

            while queue and len(visited) < self.max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                try:
                    page.goto(url, timeout=self.timeout * 1000,
                              wait_until="networkidle")
                    page.wait_for_timeout(1000)

                    # Extract forms
                    forms = page.evaluate("""() => {
                        return Array.from(document.forms).map(f => ({
                            action: f.action,
                            method: f.method,
                            fields: Array.from(f.elements).map(e => ({
                                name: e.name, type: e.type, value: e.value
                            }))
                        }));
                    }""")
                    self.forms_found.extend(forms)

                    # Extract links
                    links = page.evaluate("""() => {
                        return Array.from(document.links).map(l => l.href);
                    }""")
                    for link in links:
                        if (self.domain in link and
                            link not in visited and
                            not any(link.endswith(ext) for ext in
                                    [".png",".jpg",".css",".woff",".ico"])):
                            queue.append(link)

                    # Click common interactive elements
                    self._click_interactive(page)

                except Exception:
                    pass

            browser.close()
        return captured

    def _click_interactive(self, page):
        """Click buttons, tabs, and expandable sections."""
        selectors = [
            "button:not([type='submit'])",
            "[role='tab']",
            "[role='menuitem']",
            "a[href='#']",
            ".nav-link",
            ".dropdown-toggle",
        ]
        for sel in selectors:
            try:
                elements = page.query_selector_all(sel)
                for el in elements[:5]:
                    try:
                        el.click(timeout=2000)
                        page.wait_for_timeout(500)
                    except Exception:
                        pass
            except Exception:
                pass

    def _crawl_requests(self) -> List[Dict]:
        """Fallback: requests-based BFS crawler."""
        sess = requests.Session()
        sess.verify = False
        sess.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            **self.auth_headers
        })
        sess.cookies.update(self.session_cookies)

        captured = []
        queue    = [self.base_url]
        visited  = set()

        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                r = sess.get(url, timeout=self.timeout, allow_redirects=True)
                captured.append({
                    "method":   "GET",
                    "url":      url,
                    "headers":  dict(sess.headers),
                    "post_data":"",
                    "response_status": r.status_code,
                    "response_length": len(r.text),
                    "source":   "requests",
                })

                # Extract links
                for link in re.findall(r'href=["\']([^"\'#]+)["\']', r.text):
                    abs_link = urljoin(url, link)
                    if (self.domain in abs_link and
                        abs_link not in visited and
                        not any(abs_link.endswith(e) for e in
                                [".png",".jpg",".css",".js",".woff",".ico"])):
                        queue.append(abs_link)

                # Extract forms
                for form in re.finditer(r'<form([^>]*)>(.*?)</form>',
                                         r.text, re.DOTALL | re.I):
                    action = re.search(r'action=["\']([^"\']+)', form.group(1))
                    inputs = {}
                    for inp in re.finditer(r'<input([^>]+)>', form.group(2), re.I):
                        name = re.search(r'name=["\']([^"\']+)', inp.group(1))
                        if name:
                            inputs[name.group(1)] = ""
                    if inputs:
                        self.forms_found.append({
                            "action": urljoin(url, action.group(1)) if action else url,
                            "inputs": inputs,
                        })

                # Extract API calls from inline JS
                for api_call in re.findall(
                    r'(?:fetch|axios\.|\.get\(|\.post\()\s*\(["\']([/][^"\']+)',
                    r.text
                ):
                    abs_api = urljoin(url, api_call)
                    if self.domain in abs_api and abs_api not in visited:
                        queue.append(abs_api)

            except Exception:
                pass

        return captured


# ── Session Replay Engine (Autorize technique) ────────────────

class SessionReplayEngine:
    """
    The heart of automated IDOR detection.

    For every request captured from userA's crawl:
      1. Replay as userB → compare responses
      2. Replay unauthenticated → compare responses
      3. Replay with modified IDs → compare responses

    Response comparison:
      Same content  = no vulnerability
      Different data = IDOR found
      403 → 200     = access control bypass
      Empty → data  = information disclosure
    """

    # Similarity threshold — below this = different content = potential bug
    SIMILARITY_THRESHOLD = 0.85

    # Parameters that typically contain object IDs
    ID_PARAMS = re.compile(
        r'\b(id|uid|user_id|account_id|order_id|record_id|item_id|'
        r'doc_id|invoice_id|ticket_id|message_id|post_id|'
        r'patient_id|customer_id|profile_id|transaction_id)\b',
        re.I
    )

    def __init__(self, base_url: str,
                 session_a: dict,  # {cookies, headers}
                 session_b: dict,
                 session_none: dict = None):
        self.base_url     = base_url
        self.session_a    = session_a
        self.session_b    = session_b
        self.session_none = session_none or {}
        self.findings     : List[Dict] = []
        self._req_session  = requests.Session()
        self._req_session.verify = False

    def replay_all(self, captured_requests: List[Dict]) -> List[Dict]:
        """
        Replay all captured requests with different sessions.
        Returns list of vulnerability findings.
        """
        print(f"\n  [*] Session replay: {len(captured_requests)} requests")
        print(f"      Testing: A vs B, A vs unauthenticated, ID manipulation")

        skipped    = 0
        tested     = 0
        self.findings = []

        for req in captured_requests:
            url    = req.get("url","")
            method = req.get("method","GET")

            # Skip static assets
            if any(url.endswith(e) for e in
                   [".png",".jpg",".gif",".css",".woff",".ico",".svg"]):
                skipped += 1
                continue

            # Skip auth endpoints (login/logout/register)
            if any(p in url.lower() for p in ["/login","/logout","/register","/signup"]):
                skipped += 1
                continue

            tested += 1

            # Test 1: A vs B (same endpoint, different user)
            if self.session_b.get("cookies") or self.session_b.get("headers"):
                self._test_ab(req)

            # Test 2: A vs unauthenticated
            self._test_auth_required(req)

            # Test 3: ID manipulation in URL
            self._test_id_manipulation(req)

        print(f"  [+] Replay complete: {tested} tested, "
              f"{skipped} skipped, {len(self.findings)} findings")
        return self.findings

    def _make_request(self, method: str, url: str,
                      session_info: dict, post_data: str = "") -> Optional[requests.Response]:
        """Make a request with the given session."""
        try:
            cookies = session_info.get("cookies", {})
            headers = {
                "User-Agent": "Mozilla/5.0",
                **session_info.get("headers", {}),
            }
            if method == "GET":
                return self._req_session.get(
                    url, cookies=cookies, headers=headers, timeout=10
                )
            elif method == "POST":
                # Try to determine content type
                if post_data and post_data.strip().startswith("{"):
                    headers["Content-Type"] = "application/json"
                    return self._req_session.post(
                        url, data=post_data, cookies=cookies,
                        headers=headers, timeout=10
                    )
                else:
                    return self._req_session.post(
                        url, data=post_data, cookies=cookies,
                        headers=headers, timeout=10
                    )
        except Exception:
            return None

    def _similarity(self, r1: requests.Response,
                    r2: requests.Response) -> float:
        """Compare two responses for content similarity."""
        if not r1 or not r2:
            return 0.0
        if r1.status_code != r2.status_code:
            return 0.0
        # Jaccard on word sets
        w1 = set(re.findall(r'\w+', r1.text.lower()))
        w2 = set(re.findall(r'\w+', r2.text.lower()))
        if not w1 and not w2:
            return 1.0
        if not w1 or not w2:
            return 0.0
        return len(w1 & w2) / len(w1 | w2)

    def _test_ab(self, req: dict):
        """Test: does userB get the same data as userA?"""
        url    = req["url"]
        method = req["method"]

        r_a = self._make_request(method, url, self.session_a,
                                  req.get("post_data",""))
        r_b = self._make_request(method, url, self.session_b,
                                  req.get("post_data",""))

        if not r_a or not r_b:
            return

        # IDOR: B got 200 with different data
        if r_b.status_code == 200 and r_a.status_code == 200:
            sim = self._similarity(r_a, r_b)
            if sim < self.SIMILARITY_THRESHOLD and len(r_b.text) > 50:
                # Check if response contains sensitive data markers
                sensitive = self._has_sensitive_data(r_b.text)
                sev = "CRITICAL" if sensitive else "HIGH"
                self._add_finding(
                    title    = f"IDOR — userB accesses userA data: {self._path(url)}",
                    severity = sev,
                    url      = url,
                    method   = method,
                    evidence = (
                        f"UserA response: {r_a.status_code} ({len(r_a.text)} bytes)\n"
                        f"UserB response: {r_b.status_code} ({len(r_b.text)} bytes)\n"
                        f"Similarity: {sim:.2%} (below {self.SIMILARITY_THRESHOLD:.0%})\n"
                        f"Sensitive data: {sensitive}\n"
                        f"UserB data preview: {r_b.text[:300]}"
                    ),
                    proof_of_concept = (
                        f"# UserA request\n"
                        f"curl -s '{url}' {self._cookie_str(self.session_a)}\n\n"
                        f"# UserB request (gets UserA's data)\n"
                        f"curl -s '{url}' {self._cookie_str(self.session_b)}"
                    ),
                    cve = "CWE-639",
                )

    def _test_auth_required(self, req: dict):
        """Test: is authentication actually enforced?"""
        url    = req["url"]
        method = req["method"]

        r_auth   = self._make_request(method, url, self.session_a,
                                       req.get("post_data",""))
        r_noauth = self._make_request(method, url, {"cookies":{},"headers":{}},
                                       req.get("post_data",""))

        if not r_auth or not r_noauth:
            return

        # Access control bypass: unauthenticated gets same response as authenticated
        if (r_auth.status_code == 200 and r_noauth.status_code == 200 and
                len(r_noauth.text) > 100):
            sim = self._similarity(r_auth, r_noauth)
            if sim > 0.7:  # Similar content = no auth required
                self._add_finding(
                    title    = f"Broken Auth — Endpoint accessible without login: {self._path(url)}",
                    severity = "HIGH",
                    url      = url,
                    method   = method,
                    evidence = (
                        f"Authenticated: {r_auth.status_code} ({len(r_auth.text)}b)\n"
                        f"Unauthenticated: {r_noauth.status_code} ({len(r_noauth.text)}b)\n"
                        f"Similarity: {sim:.2%}\n"
                        f"Unauthenticated preview: {r_noauth.text[:300]}"
                    ),
                    proof_of_concept = (
                        f"# No auth needed:\n"
                        f"curl -s '{url}'"
                    ),
                    cve = "CWE-306",
                )

        # 403 → 200 bypass via header manipulation
        if r_auth.status_code == 200 and r_noauth.status_code == 403:
            for header_bypass in [
                {"X-Original-URL": urlparse(url).path},
                {"X-Rewrite-URL":  urlparse(url).path},
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                {"X-Forwarded-For": "127.0.0.1"},
            ]:
                r_bypass = self._make_request(
                    method, url,
                    {"cookies": {}, "headers": header_bypass},
                    req.get("post_data","")
                )
                if r_bypass and r_bypass.status_code == 200:
                    self._add_finding(
                        title    = f"403 Bypass via {list(header_bypass.keys())[0]}: {self._path(url)}",
                        severity = "HIGH",
                        url      = url,
                        method   = method,
                        evidence = (
                            f"Normal: 403\n"
                            f"With {list(header_bypass.keys())[0]}: 200\n"
                            f"Response: {r_bypass.text[:200]}"
                        ),
                        proof_of_concept = (
                            f"curl -s '{url}' "
                            f"-H '{list(header_bypass.keys())[0]}: {list(header_bypass.values())[0]}'"
                        ),
                        cve = "CWE-284",
                    )
                    break

    def _test_id_manipulation(self, req: dict):
        """Test ID parameters in URL for sequential/predictable access."""
        url    = req["url"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param, values in params.items():
            if not self.ID_PARAMS.search(param):
                continue
            original_val = values[0] if values else ""
            if not original_val:
                continue

            # Try to determine if it's numeric
            try:
                orig_int = int(original_val)
                test_ids = [orig_int-1, orig_int+1, orig_int+2, 1, 2, 3]
            except ValueError:
                # Not numeric — try UUID manipulation
                if re.match(r'[0-9a-f-]{36}', original_val):
                    # Keep same UUID but use known IDs
                    test_ids = []  # UUID manipulation is trickier
                    continue
                continue

            r_orig = self._make_request("GET", url, self.session_a)
            if not r_orig or r_orig.status_code != 200:
                continue

            for test_id in test_ids:
                if test_id == orig_int:
                    continue
                # Build test URL
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = str(test_id)
                test_url = (parsed.scheme + "://" + parsed.netloc +
                            parsed.path + "?" + urlencode(test_params))

                r_test = self._make_request("GET", test_url, self.session_a)
                if not r_test or r_test.status_code != 200:
                    continue

                # Different content + substantial response = different object accessed
                sim = self._similarity(r_orig, r_test)
                if sim < 0.7 and len(r_test.text) > 50:
                    sensitive = self._has_sensitive_data(r_test.text)
                    self._add_finding(
                        title    = f"IDOR — Sequential ID access: {param}={test_id} at {self._path(url)}",
                        severity = "CRITICAL" if sensitive else "HIGH",
                        url      = test_url,
                        method   = "GET",
                        evidence = (
                            f"Original: {param}={orig_int} → {r_orig.status_code}\n"
                            f"Modified: {param}={test_id} → {r_test.status_code}\n"
                            f"Different content returned (sim={sim:.2%})\n"
                            f"Sensitive: {sensitive}\n"
                            f"Data: {r_test.text[:300]}"
                        ),
                        proof_of_concept = f"curl -s '{test_url}'",
                        cve = "CWE-639",
                    )
                    break  # Found one, move to next param

    def _has_sensitive_data(self, text: str) -> List[str]:
        """Detect sensitive data in response."""
        indicators = []
        patterns = {
            "email":    r'[\w.+-]+@[\w-]+\.[\w.-]+',
            "phone":    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "ssn":      r'\b\d{3}-\d{2}-\d{4}\b',
            "credit":   r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            "password": r'"password"\s*:\s*"[^"]+"',
            "token":    r'"(?:token|api_key|secret)"\s*:\s*"[^"]{10,}"',
            "pii_field":r'"(?:ssn|dob|birthdate|address|bank_account)"\s*:',
        }
        for data_type, pattern in patterns.items():
            if re.search(pattern, text, re.I):
                indicators.append(data_type)
        return indicators

    def _add_finding(self, title: str, severity: str, url: str,
                     method: str, evidence: str, proof_of_concept: str,
                     cve: str = ""):
        """Add a finding with deduplication."""
        sig = hashlib.md5(f"{title}|{url}".encode()).hexdigest()[:12]
        if any(f.get("sig") == sig for f in self.findings):
            return
        finding = {
            "title":              title,
            "severity":           severity,
            "module":             "automate",
            "url":                url,
            "method":             method,
            "description":        (
                f"Automated session replay detected an access control vulnerability. "
                f"{title}"
            ),
            "evidence":           evidence,
            "proof_of_concept":   proof_of_concept,
            "remediation":        (
                "Implement server-side authorization on every request. "
                "Verify the authenticated user owns the requested object. "
                "Do not rely on client-supplied IDs without ownership verification."
            ),
            "cve":                cve,
            "timestamp":          datetime.now().isoformat(),
            "sig":                sig,
        }
        self.findings.append(finding)
        sev_color = {
            "CRITICAL": "\033[91m",
            "HIGH":     "\033[93m",
        }.get(severity, "\033[97m")
        print(f"  {sev_color}[{severity}]\033[0m {title[:70]}")

    def _path(self, url: str) -> str:
        return urlparse(url).path

    def _cookie_str(self, session: dict) -> str:
        cookies = session.get("cookies", {})
        if cookies:
            return "-H 'Cookie: " + "; ".join(f"{k}={v}" for k,v in cookies.items()) + "'"
        if session.get("headers", {}).get("Authorization"):
            return f"-H 'Authorization: {session['headers']['Authorization']}'"
        return ""


# ── Parameter Injection Engine ────────────────────────────────

class ParameterInjectionEngine:
    """
    For every form and JSON endpoint discovered:
      - Inject hidden privilege parameters (role, isAdmin, etc.)
      - Test mass assignment
      - Test parameter pollution
    """

    PRIVILEGE_PARAMS = [
        {"role": "admin"},
        {"role": "administrator"},
        {"isAdmin": True},
        {"is_admin": True},
        {"admin": True},
        {"superuser": True},
        {"privilege": "admin"},
        {"permissions": ["admin", "superuser"]},
        {"user_type": "admin"},
        {"account_type": "premium"},
        {"subscription": "enterprise"},
        {"credits": 999999},
        {"balance": 99999.99},
    ]

    def __init__(self, base_url: str, session: dict):
        self.base_url = base_url
        self.session  = session
        self._req     = requests.Session()
        self._req.verify = False
        self._req.headers.update({
            "User-Agent": "Mozilla/5.0",
            **session.get("headers", {})
        })
        self._req.cookies.update(session.get("cookies", {}))
        self.findings: List[Dict] = []

    def inject_all(self, forms: List[Dict], api_endpoints: List[str]) -> List[Dict]:
        """Test all forms and endpoints for parameter injection."""
        print(f"\n  [*] Parameter injection: {len(forms)} forms, "
              f"{len(api_endpoints)} endpoints")

        for form in forms[:20]:
            self._inject_form(form)

        for endpoint in api_endpoints[:20]:
            self._inject_api(endpoint)

        print(f"  [+] Parameter injection: {len(self.findings)} findings")
        return self.findings

    def _inject_form(self, form: dict):
        """Inject privilege params into a form."""
        action = form.get("action", "")
        if not action.startswith("http"):
            action = self.base_url + action

        base_data = dict(form.get("inputs", {}))

        for extra_params in self.PRIVILEGE_PARAMS[:6]:
            data = {**base_data, **{k: str(v) for k,v in extra_params.items()}}
            try:
                r = self._req.post(action, data=data, timeout=10,
                                   allow_redirects=True)
                if r.status_code in [200, 201]:
                    # Check if privilege param reflected
                    for key, val in extra_params.items():
                        if str(val).lower() in r.text.lower():
                            self.findings.append({
                                "title":      f"Mass Assignment — '{key}' accepted at {action}",
                                "severity":   "CRITICAL",
                                "module":     "automate",
                                "url":        action,
                                "parameter":  key,
                                "payload":    str(extra_params),
                                "description":f"Privilege parameter '{key}={val}' accepted and reflected.",
                                "evidence":   f"Form: {action}\nExtra: {extra_params}\nReflected: {key}",
                                "remediation":"Use explicit field allowlists. Never bind raw request to model.",
                                "cve":        "CWE-915",
                                "timestamp":  datetime.now().isoformat(),
                            })
                            print(f"  \033[91m[CRITICAL]\033[0m Mass assignment: {key} at {action}")
                            return
            except Exception:
                pass

    def _inject_api(self, endpoint: str):
        """Test API endpoint for mass assignment."""
        for extra_params in self.PRIVILEGE_PARAMS[:4]:
            payload = extra_params
            try:
                r = self._req.post(endpoint, json=payload, timeout=10)
                if r.status_code in [200, 201]:
                    for key, val in extra_params.items():
                        if str(val).lower() in r.text.lower():
                            self.findings.append({
                                "title":      f"Mass Assignment via API — '{key}': {endpoint}",
                                "severity":   "CRITICAL",
                                "module":     "automate",
                                "url":        endpoint,
                                "parameter":  key,
                                "payload":    json.dumps(extra_params),
                                "description":f"API accepts privilege parameter '{key}'.",
                                "evidence":   f"POST {endpoint}\nPayload: {json.dumps(extra_params)}",
                                "remediation":"Validate and whitelist all accepted parameters.",
                                "cve":        "CWE-915",
                                "timestamp":  datetime.now().isoformat(),
                            })
                            print(f"  \033[91m[CRITICAL]\033[0m API mass assignment: {key} at {endpoint}")
                            return
            except Exception:
                pass


# ── Main AutomateEngine ───────────────────────────────────────

class AutomateEngine:
    """
    Master controller for fully automated deep dive.
    Replaces 4-6 hours of manual testing.
    """

    def __init__(self, target: str,
                 credentials: List[Dict] = None,
                 max_pages: int = 100,
                 timeout: int = 30):
        self.target      = target.rstrip("/")
        self.credentials = credentials or []
        self.max_pages   = max_pages
        self.timeout     = timeout
        self.findings    : List[Dict] = []
        self._accounts   : List[Dict] = []

    def run(self) -> dict:
        """Execute the full automated deep dive."""
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║  AutomateEngine — Full Automated Deep Dive                ║
║  Target: {self.target[:50]:<50} ║
╚═══════════════════════════════════════════════════════════╝""")

        # Step 1: Get accounts (register or use provided)
        sessions = self._setup_sessions()
        if len(sessions) < 1:
            print("  [!] No sessions available — scan unauthenticated only")
            sessions.append({"cookies": {}, "headers": {}, "role": "anonymous"})

        session_a    = sessions[0] if len(sessions) >= 1 else {}
        session_b    = sessions[1] if len(sessions) >= 2 else {}
        session_admin= next((s for s in sessions if s.get("role")=="admin"), {})

        print(f"\n  Sessions: {len(sessions)} available")
        for s in sessions:
            print(f"    - {s.get('role','?')}: {s.get('username','anonymous')}")

        # Step 2: Authenticated crawl as userA
        print(f"\n  [*] Phase 1: Authenticated crawl as userA...")
        crawler_a = AuthenticatedCrawler(
            self.target,
            session_cookies=session_a.get("cookies",{}),
            auth_headers   =session_a.get("headers",{}),
            max_pages      =self.max_pages,
            timeout        =self.timeout,
        )
        requests_a = crawler_a.crawl()
        forms_a    = crawler_a.forms_found
        print(f"  [+] Captured {len(requests_a)} requests, {len(forms_a)} forms")

        # Step 3: Admin crawl (find privileged endpoints)
        requests_admin = []
        if session_admin:
            print(f"\n  [*] Phase 2: Admin crawl...")
            crawler_admin = AuthenticatedCrawler(
                self.target,
                session_cookies=session_admin.get("cookies",{}),
                auth_headers   =session_admin.get("headers",{}),
                max_pages      =self.max_pages // 2,
            )
            requests_admin = crawler_admin.crawl()
            print(f"  [+] Admin captured {len(requests_admin)} requests")

        # Step 4: Session replay (A vs B vs unauthenticated)
        print(f"\n  [*] Phase 3: Session replay engine (Autorize)...")
        all_requests = requests_a + requests_admin

        replay = SessionReplayEngine(
            self.target,
            session_a    = session_a,
            session_b    = session_b,
            session_none = {"cookies":{},"headers":{}},
        )
        idor_findings = replay.replay_all(all_requests)
        self.findings.extend(idor_findings)

        # Step 5: Parameter injection on all forms
        print(f"\n  [*] Phase 4: Parameter injection engine...")
        api_endpoints = list(set(
            r["url"] for r in all_requests
            if "/api/" in r["url"] and r["method"] == "POST"
        ))
        injector = ParameterInjectionEngine(self.target, session_a)
        inject_findings = injector.inject_all(forms_a, api_endpoints)
        self.findings.extend(inject_findings)

        # Summary
        crits = sum(1 for f in self.findings if f.get("severity")=="CRITICAL")
        highs = sum(1 for f in self.findings if f.get("severity")=="HIGH")

        print(f"""
╔═══════════════════════════════════════════════════════════╗
║  AutomateEngine Complete                                  ║
║  Requests tested: {len(all_requests):<41} ║
║  Findings:  CRITICAL={crits}  HIGH={highs:<33} ║
╚═══════════════════════════════════════════════════════════╝""")

        return {
            "target":   self.target,
            "findings": self.findings,
            "requests_tested": len(all_requests),
            "sessions": len(sessions),
        }

    def _setup_sessions(self) -> List[Dict]:
        """Set up sessions from credentials or auto-register."""
        sessions = []

        if self.credentials:
            # Log in with provided credentials
            from core.auth_engine import ScanAuthEngine
            engine = ScanAuthEngine(self.target, self.timeout)
            for cred in self.credentials:
                engine.add_credential(
                    cred.get("username",""),
                    cred.get("password",""),
                    cred.get("role","user"),
                )
            engine.login_all()
            for sess in engine.get_all_sessions():
                sessions.append({
                    "username": sess.username,
                    "role":     sess.role,
                    "cookies":  dict(sess.session.cookies),
                    "headers":  sess.auth_headers(),
                    "user_id":  sess.user_id,
                })
        else:
            # Auto-register two accounts
            print("\n  [*] No credentials — attempting auto-registration...")
            registrar = AutoRegistrar(self.target, self.timeout)

            acc_a = registrar.create_account("user", "amonstrike_a")
            acc_b = registrar.create_account("user", "amonstrike_b")

            if acc_a:
                # Log in with new account
                from core.auth_engine import ScanAuthEngine
                engine = ScanAuthEngine(self.target, self.timeout)
                for acc in [acc_a, acc_b]:
                    if acc:
                        engine.add_credential(acc["email"], acc["password"])
                engine.login_all()
                for sess in engine.get_all_sessions():
                    sessions.append({
                        "username": sess.username,
                        "role":     "user",
                        "cookies":  dict(sess.session.cookies),
                        "headers":  sess.auth_headers(),
                    })

        return sessions


def run_regression_tests():
    print("\n=== AUTOMATE ENGINE REGRESSION TESTS ===")
    passed = failed = 0

    # TempMail
    tm = TempMailClient()
    # AutoRegistrar
    reg = AutoRegistrar("http://testphp.vulnweb.com")
    # AuthenticatedCrawler
    crawler = AuthenticatedCrawler("http://testphp.vulnweb.com", max_pages=5)
    # SessionReplayEngine
    replay = SessionReplayEngine(
        "http://testphp.vulnweb.com",
        session_a    = {"cookies":{},"headers":{}},
        session_b    = {"cookies":{},"headers":{}},
        session_none = {"cookies":{},"headers":{}},
    )
    # ParameterInjectionEngine
    injector = ParameterInjectionEngine(
        "http://testphp.vulnweb.com", {"cookies":{},"headers":{}}
    )
    # AutomateEngine
    engine = AutomateEngine("http://testphp.vulnweb.com", max_pages=5)

    tests = [
        ("TempMailClient instantiates",
         lambda: isinstance(tm, TempMailClient)),

        ("TempMail create returns email dict",
         lambda: "@" in tm.create().get("email","")),

        ("TempMail email has valid format",
         lambda: re.match(r'[\w.+-]+@[\w-]+\.\w+', tm.create()["email"]) is not None),

        ("AutoRegistrar instantiates",
         lambda: isinstance(reg, AutoRegistrar)),

        ("AutoRegistrar has register paths",
         lambda: len(AutoRegistrar.REGISTER_PATHS) >= 8),

        ("AuthenticatedCrawler instantiates",
         lambda: isinstance(crawler, AuthenticatedCrawler)),

        ("Crawler domain extracted",
         lambda: crawler.domain == "testphp.vulnweb.com"),

        ("SessionReplayEngine instantiates",
         lambda: isinstance(replay, SessionReplayEngine)),

        ("Similarity identical texts = 1.0",
         lambda: abs(replay._similarity(
             type('R',(),{'status_code':200,'text':'hello world test'})(),
             type('R',(),{'status_code':200,'text':'hello world test'})()
         ) - 1.0) < 0.01),

        ("Similarity different texts < 0.5",
         lambda: replay._similarity(
             type('R',(),{'status_code':200,'text':'hello world admin user data'})(),
             type('R',(),{'status_code':200,'text':'completely different content xyz abc'})()
         ) < 0.5),

        ("Similarity different status = 0.0",
         lambda: replay._similarity(
             type('R',(),{'status_code':200,'text':'hello'})(),
             type('R',(),{'status_code':403,'text':'hello'})()
         ) == 0.0),

        ("Sensitive data detection finds email",
         lambda: "email" in replay._has_sensitive_data("user@test.com found")),

        ("Sensitive data detection finds credit card",
         lambda: "credit" in replay._has_sensitive_data("4111 1111 1111 1111")),

        ("No sensitive data in generic text",
         lambda: len(replay._has_sensitive_data("hello world foo bar")) == 0),

        ("ID_PARAMS regex matches id param",
         lambda: replay.ID_PARAMS.search("user_id") is not None),

        ("ID_PARAMS regex matches order_id",
         lambda: replay.ID_PARAMS.search("order_id") is not None),

        ("ParameterInjectionEngine instantiates",
         lambda: isinstance(injector, ParameterInjectionEngine)),

        ("Privilege params populated",
         lambda: len(ParameterInjectionEngine.PRIVILEGE_PARAMS) >= 8),

        ("Privilege params include isAdmin",
         lambda: any("isAdmin" in str(p) for p in ParameterInjectionEngine.PRIVILEGE_PARAMS)),

        ("AutomateEngine instantiates",
         lambda: isinstance(engine, AutomateEngine)),

        ("AutomateEngine has target",
         lambda: engine.target == "http://testphp.vulnweb.com"),
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
    if len(sys.argv) > 1:
        creds = None
        if len(sys.argv) > 2:
            creds = json.loads(sys.argv[2])
        engine = AutomateEngine(sys.argv[1], credentials=creds, max_pages=50)
        result = engine.run()
        print(f"\nFindings: {len(result['findings'])}")
    else:
        run_regression_tests()
