"""
AmonStrike — Aggressive Surface Discovery
Finds the REAL attack surface on production apps.

The problem: Real apps like api.zomato.com don't have
?artist=1 on their homepage. The tool needs to:

1. Find ALL real API endpoints (not guess from HTML links)
2. Find JS files and extract API calls from them
3. Check wayback machine for historical endpoints
4. Use wordlists to discover hidden endpoints
5. Analyze mobile app API calls (from public sources)
6. Find GraphQL, WebSocket, REST endpoints

This is what real researchers do before touching a target.
"""

import re
import json
import time
import requests
import urllib3
from urllib.parse import urlparse, urljoin
from pathlib import Path

urllib3.disable_warnings()

# API endpoint wordlist — common patterns on real apps
API_WORDLIST = [
    # Claude.ai + Anthropic console specific
    "/api/auth/session",
    "/api/organizations",
    "/api/account",
    "/api/bootstrap",
    "/api/usage",
    "/api/billing",
    "/api/limits",
    "/api/models",
    "/api/organizations/unknown/chat_conversations",
    "/api/organizations/unknown/api_keys",
    "/api/organizations/unknown/members",
    "/api/organizations/unknown/settings",
    "/api/organizations/unknown/usage",
    "/api/organizations/unknown/workspaces",
    "/api/organizations/unknown/invites",

    # Auth
    "/api/auth/login", "/api/auth/register", "/api/auth/token",
    "/api/auth/refresh", "/api/v1/auth/login", "/api/v2/auth/login",
    "/auth/login", "/auth/token", "/oauth/token", "/oauth2/token",
    "/login", "/signup", "/register",

    # User
    "/api/user", "/api/user/me", "/api/user/profile",
    "/api/users", "/api/users/me", "/api/v1/users",
    "/api/v2/users", "/user/profile", "/user/account",
    "/api/account", "/api/me", "/api/profile",

    # Search
    "/api/search", "/api/v1/search", "/api/v2/search",
    "/search", "/api/restaurants", "/api/v1/restaurants",
    "/api/v2.1/restaurants", "/api/explore",

    # Orders
    "/api/orders", "/api/order", "/api/v1/orders",
    "/api/v2/orders", "/api/checkout", "/api/cart",
    "/api/basket", "/api/transactions",

    # Data
    "/api/data", "/api/feed", "/api/home",
    "/api/config", "/api/settings", "/api/status",
    "/api/health", "/api/version",

    # Admin
    "/api/admin", "/admin/api", "/api/v1/admin",
    "/api/internal", "/internal/api",

    # Zomato specific
    "/api/v2.1/search", "/api/v2.1/restaurant",
    "/api/v2.1/review_listing", "/api/v2.1/user",
    "/api/v2.1/collections", "/api/v2.1/cuisine",
    "/api/v2.1/location", "/api/v2.1/categories",
    "/api/v2.1/geocode", "/api/v2.1/cities",
    "/v2.1/search", "/v2.1/restaurant", "/v2.1/user",

    # Blinkit specific
    "/api/v1/products", "/api/v1/categories",
    "/api/v1/cart", "/api/v1/orders", "/api/v1/user",
    "/api/v2/products", "/api/v2/search",

    # GraphQL
    "/graphql", "/api/graphql", "/v1/graphql",
    "/gql", "/api/gql",

    # Misc
    "/sitemap.xml", "/robots.txt", "/.well-known/security.txt",
    "/api-docs", "/swagger.json", "/openapi.json",
    "/api/swagger", "/docs/api",
]

# JS file patterns that contain API endpoints
JS_API_PATTERNS = [
    r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\']([/][^"\']+)',
    r'(?:url|endpoint|path|api)\s*[:=]\s*["\']([/api][^"\']+)',
    r'["\']((?:/api/|/v\d/)[^"\'<>\s,;]+)["\']',
    r'baseURL\s*[:=]\s*["\']([^"\']+)',
    r'(?:GET|POST|PUT|DELETE|PATCH)\s+["\']([/][^"\']+)',
]


class AggressiveSurfaceDiscovery:
    """
    Finds the real attack surface.
    Used BEFORE modules run.
    """

    def __init__(self, target: str, session: requests.Session = None,
                 extra_headers: dict = None):
        self.target  = target.rstrip("/")
        self.parsed  = urlparse(target)
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        if extra_headers:
            self.session.headers.update(extra_headers)
        self.endpoints   = set()
        self.js_files    = set()
        self.api_calls   = set()
        self.interesting = []

    def run(self) -> dict:
        """Full surface discovery."""
        print(f"  [SURFACE] Discovering attack surface for {self.target}")

        self._probe_common_endpoints()
        self._find_js_files()
        self._extract_from_js()
        self._check_wayback()
        self._check_common_files()

        print(f"  [SURFACE] Found: {len(self.endpoints)} endpoints, "
              f"{len(self.js_files)} JS files, "
              f"{len(self.api_calls)} API calls")

        return {
            "endpoints":   list(self.endpoints),
            "js_files":    list(self.js_files),
            "api_calls":   list(self.api_calls),
            "interesting": self.interesting,
        }

    def _probe_common_endpoints(self):
        """Probe common API endpoints with wordlist."""
        alive = []
        for path in API_WORDLIST:
            url = self.target + path
            try:
                r = self.session.get(url, timeout=5, allow_redirects=True)
                if r.status_code in [200, 201, 301, 302, 401, 403, 405]:
                    # 401/403 = endpoint exists, just needs auth
                    # 405 = endpoint exists, wrong method
                    alive.append(url)
                    self.endpoints.add(url)

                    if r.status_code in [200, 201]:
                        # Check what's in response
                        self._analyze_response(url, r)

                    # Small delay — don't hammer
                    time.sleep(0.1)
            except Exception:
                pass

        print(f"  [SURFACE] Wordlist probe: {len(alive)} live endpoints")

    def _find_js_files(self):
        """Find JavaScript files that contain API calls."""
        try:
            r = self.session.get(self.target, timeout=10)
            if not r:
                return

            # Find JS file URLs
            js_urls = set()
            for pattern in [
                r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
                r'["\']([^"\']+chunk[^"\']*\.js)["\']',
                r'["\']([^"\']+bundle[^"\']*\.js)["\']',
                r'["\']([^"\']+main[^"\']*\.js)["\']',
                r'["\']([^"\']+app[^"\']*\.js)["\']',
            ]:
                for m in re.finditer(pattern, r.text, re.I):
                    js_url = m.group(1)
                    if not js_url.startswith("http"):
                        js_url = urljoin(self.target, js_url)
                    if self.parsed.netloc in js_url or js_url.startswith("/"):
                        js_urls.add(js_url)

            self.js_files.update(js_urls)
            print(f"  [SURFACE] JS files found: {len(js_urls)}")

        except Exception:
            pass

    def _extract_from_js(self):
        """Extract API endpoints from JS files."""
        for js_url in list(self.js_files)[:20]:
            try:
                r = self.session.get(js_url, timeout=10)
                if not r or r.status_code != 200:
                    continue

                # Extract API endpoints
                for pattern in JS_API_PATTERNS:
                    for m in re.finditer(pattern, r.text):
                        endpoint = m.group(1)
                        if any(skip in endpoint for skip in
                               [".css", ".png", ".jpg", ".svg", "#"]):
                            continue
                        if endpoint.startswith("/"):
                            full_url = self.target + endpoint
                        elif endpoint.startswith("http"):
                            full_url = endpoint
                        else:
                            continue
                        self.api_calls.add(full_url)
                        self.endpoints.add(full_url)

                # Extract API keys/tokens (might be hardcoded)
                for secret_pattern in [
                    r'(?:api[_-]?key|apikey|token|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',
                    r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']',  # base64
                ]:
                    for m in re.finditer(secret_pattern, r.text, re.I):
                        val = m.group(1)
                        if len(val) > 20 and not val.startswith("AAAA"):
                            self.interesting.append({
                                "type":    "possible_secret",
                                "value":   val[:60],
                                "source":  js_url,
                            })

            except Exception:
                pass

        if self.api_calls:
            print(f"  [SURFACE] API calls from JS: {len(self.api_calls)}")

    def _check_wayback(self):
        """Get historical endpoints from Wayback Machine."""
        domain = self.parsed.netloc
        try:
            r = self.session.get(
                f"https://web.archive.org/cdx/search/cdx",
                params={
                    "url":      f"{domain}/*",
                    "output":   "text",
                    "fl":       "original",
                    "collapse": "urlkey",
                    "limit":    "200",
                    "filter":   "statuscode:200",
                },
                timeout=15,
            )
            if r.status_code == 200:
                urls = r.text.strip().splitlines()
                api_urls = [u for u in urls if "/api/" in u or "?" in u]
                for url in api_urls[:50]:
                    # Convert wayback URL to live URL
                    p = urlparse(url)
                    if p.netloc == domain:
                        self.endpoints.add(url)

                print(f"  [SURFACE] Wayback: {len(api_urls)} historical API URLs")
        except Exception:
            pass

    def _check_common_files(self):
        """Check for exposed sensitive files."""
        sensitive = [
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/.env", "/.git/HEAD", "/config.json",
        ]
        for path in sensitive:
            try:
                r = self.session.get(self.target + path, timeout=5)
                if r.status_code == 200 and len(r.text) > 20:
                    self.endpoints.add(self.target + path)
                    self.interesting.append({
                        "type":    "sensitive_file",
                        "path":    path,
                        "size":    len(r.text),
                        "preview": r.text[:100],
                    })
            except Exception:
                pass

    def _analyze_response(self, url: str, r: requests.Response):
        """Analyze a 200 response for interesting data."""
        try:
            data = r.json()
            # Check for sensitive fields
            data_str = json.dumps(data).lower()
            sensitive_fields = ["password","secret","token","key","ssn",
                               "credit_card","phone","email","address"]
            found = [f for f in sensitive_fields if f in data_str]
            if found:
                self.interesting.append({
                    "type":   "sensitive_data_in_response",
                    "url":    url,
                    "fields": found,
                    "preview": json.dumps(data)[:200],
                })
        except Exception:
            pass


class AuthenticatedSurfaceDiscovery(AggressiveSurfaceDiscovery):
    """
    Surface discovery with authentication.
    Finds endpoints that require login.
    """

    def __init__(self, target: str, session: requests.Session,
                 user_a_cookies: dict, user_b_cookies: dict = None,
                 extra_headers: dict = None):
        super().__init__(target, session, extra_headers)
        self.session_a = requests.Session()
        self.session_a.verify = False
        self.session_a.cookies.update(user_a_cookies)
        self.session_a.headers.update(session.headers)

        self.session_b = None
        if user_b_cookies:
            self.session_b = requests.Session()
            self.session_b.verify = False
            self.session_b.cookies.update(user_b_cookies)
            self.session_b.headers.update(session.headers)

    def find_idor_candidates(self) -> list:
        """
        Find endpoints where User A can access User B's data.
        Core IDOR detection.
        """
        candidates = []
        for endpoint in list(self.endpoints)[:30]:
            try:
                r_a = self.session_a.get(endpoint, timeout=8)
                if not r_a or r_a.status_code != 200:
                    continue

                # Extract IDs from response
                ids = re.findall(r'"(?:id|user_id|userId|uid)"\s*:\s*(\d+)', r_a.text)
                if not ids:
                    continue

                # Try to access those IDs as different user
                for id_val in ids[:3]:
                    test_url = re.sub(r'/\d+', f'/{id_val}', endpoint)
                    if test_url == endpoint:
                        continue

                    if self.session_b:
                        r_b = self.session_b.get(test_url, timeout=8)
                    else:
                        # Unauthenticated
                        r_b = self.session.get(test_url, timeout=8)

                    if r_b and r_b.status_code == 200:
                        import hashlib
                        if (hashlib.md5(r_a.text.encode()).hexdigest() !=
                                hashlib.md5(r_b.text.encode()).hexdigest()):
                            candidates.append({
                                "url":       test_url,
                                "id":        id_val,
                                "different": True,
                            })

            except Exception:
                pass

        return candidates
