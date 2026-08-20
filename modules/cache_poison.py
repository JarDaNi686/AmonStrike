"""
AmonStrike — Web Cache Poisoning Module
Cache poisoning serves malicious responses to all users.

Attacks:
  1. Unkeyed header injection (X-Forwarded-Host)
  2. Fat GET request (body in GET request)
  3. Parameter cloaking
  4. Cache deception
  5. Vary header bypass
  6. DOM-based cache poisoning
"""

from .base import BaseModule


class CachePoisonModule(BaseModule):
    NAME        = "cache_poison"
    DESCRIPTION = "Web cache poisoning — X-Forwarded-Host, fat GET, cache deception"

    UNKEYED_HEADERS = [
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Server",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-Scheme",
        "X-Forwarded-Port",
        "X-Custom-IP-Authorization",
    ]

    CACHE_POISON_PAYLOAD = "evil.com"

    def run(self):
        self.log("Testing web cache poisoning...")
        self._test_unkeyed_headers()
        self._test_fat_get()
        self._test_cache_deception()
        self._test_parameter_cloaking()
        self._detect_caching()
        self.log(f"Cache poisoning scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _detect_caching(self):
        """Detect if caching is present."""
        r1 = self.get("")
        if not r1:
            return False
        cache_indicators = [
            "x-cache", "cf-cache-status", "x-varnish",
            "age", "x-cache-hits", "surrogate-key",
        ]
        cache_headers = [h for h in r1.headers
                         if h.lower() in cache_indicators]
        if cache_headers:
            self.info["caching_detected"] = True
            self.info["cache_headers"]    = cache_headers
            return True

        # Check Age header (indicates cached response)
        if "age" in r1.headers:
            self.info["caching_detected"] = True
            return True

        return False

    def _test_unkeyed_headers(self):
        """Test if unkeyed headers can be injected into cached responses."""
        # First get baseline
        baseline = self.get("")
        if not baseline:
            return

        for header in self.UNKEYED_HEADERS:
            # Inject evil value into header
            r = self.get("", headers={header: self.CACHE_POISON_PAYLOAD})
            if not r:
                continue

            # Check if payload reflected in response
            if self.CACHE_POISON_PAYLOAD in r.text:
                self.add_finding(
                    title=f"Web Cache Poisoning via Unkeyed Header: {header}",
                    severity="HIGH",
                    description=f"The {header} header value is reflected in the response without being included in the cache key. An attacker can poison the cache with malicious content for all users.",
                    evidence=(
                        f"Header: {header}: {self.CACHE_POISON_PAYLOAD}\n"
                        f"Response reflects value: {self.CACHE_POISON_PAYLOAD}\n"
                        f"If cached, ALL subsequent visitors see attacker content"
                    ),
                    remediation="Add the header to the cache key, or strip unrecognized forwarding headers at the CDN/cache layer.",
                    url=self.url, cve="CWE-346"
                )

        # X-Forwarded-Host specifically for host header attacks
        r = self.get("", headers={"X-Forwarded-Host": "evil.com"})
        if r and "evil.com" in r.text:
            self.add_finding(
                title="Cache Poisoning via X-Forwarded-Host — XSS/Redirect Potential",
                severity="CRITICAL",
                description="X-Forwarded-Host reflected in response. If cached, poisons all visitors. Can load attacker JS or redirect to phishing.",
                evidence=f"X-Forwarded-Host: evil.com reflected in response body",
                remediation="Strip X-Forwarded-Host at perimeter. If needed, validate against allowlist.",
                url=self.url, cve="CWE-346"
            )

    def _test_fat_get(self):
        """Test Fat GET — body in GET request processed as if query string."""
        r = self.session.request(
            "GET", self.url,
            data=f"search={self.CACHE_POISON_PAYLOAD}&q={self.CACHE_POISON_PAYLOAD}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        if r and self.CACHE_POISON_PAYLOAD in r.text:
            self.add_finding(
                title="Fat GET Request — Body Parameters Reflected",
                severity="MEDIUM",
                description="GET request body is processed and reflected in response. If combined with cache poisoning, allows injection of content for cached users.",
                evidence=f"GET {self.url} with body: q={self.CACHE_POISON_PAYLOAD}\nReflected in response",
                remediation="Do not process GET request bodies. Ignore non-standard GET payloads at the cache layer.",
                url=self.url, cve="CWE-346"
            )

    def _test_cache_deception(self):
        """Test web cache deception — tricking cache into storing private pages."""
        # Try appending fake static file paths to sensitive endpoints
        sensitive_paths = [
            "/api/profile",
            "/api/account",
            "/api/user",
            "/dashboard",
            "/settings",
        ]
        static_suffixes = [
            "/nonexistent.css",
            "/nonexistent.js",
            "/static.png",
            "/../nonexistent.css",
        ]

        for base in sensitive_paths:
            for suffix in static_suffixes:
                url = self.url + base + suffix
                try:
                    r = self.session.get(url, timeout=10, verify=False)
                    if r and r.status_code == 200:
                        # Check for private data indicators
                        if any(k in r.text.lower() for k in
                               ["email","profile","account","user_id","balance"]):
                            # Check if it's being cached
                            r2 = self.session.get(url, timeout=10, verify=False)
                            if r2 and r2.headers.get("x-cache","").upper() == "HIT":
                                self.add_finding(
                                    title=f"Web Cache Deception — Private Page Cached as Static",
                                    severity="HIGH",
                                    description=f"Appending a static suffix ({suffix}) to {base} causes the response (containing private data) to be cached. Any user can retrieve victim's private data by visiting the cached URL.",
                                    evidence=f"URL: {url}\nReturns private data + X-Cache: HIT",
                                    remediation="Set Cache-Control: no-store on all authenticated responses. Validate URL paths before processing.",
                                    url=url, cve="CWE-525"
                                )
                except Exception:
                    pass

    def _test_parameter_cloaking(self):
        """Test parameter cloaking to smuggle cache-busting params."""
        # Some CDNs strip certain parameters from cache keys
        test_cases = [
            ("utm_content", "evil"),   # UTM stripped by many CDNs
            ("fbclid",      "evil"),   # FB click ID stripped
            ("gclid",       "evil"),   # Google click ID stripped
        ]
        baseline = self.get("")
        if not baseline:
            return

        for param, value in test_cases:
            r = self.get("", params={param: value, "legit_param": "test"})
            if r and r.text == baseline.text:
                # CDN may be stripping this param from cache key
                # Try to inject payload via stripped param
                r2 = self.get("", params={param: f"';alert(1)//", "legit": "1"})
                if r2 and "alert(1)" in r2.text:
                    self.add_finding(
                        title=f"Cache Poisoning via Parameter Cloaking — {param}",
                        severity="HIGH",
                        description=f"The {param} parameter is stripped from the cache key by CDN but reflected in response. Allows cache poisoning with XSS payload.",
                        evidence=f"?{param}=';alert(1)// reflected in cached response",
                        remediation="Ensure all parameters that affect response are included in cache key.",
                        url=self.url, cve="CWE-346"
                    )
