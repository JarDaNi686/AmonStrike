"""
AmonStrike — Scope Validator (Legal Protection Engine)
CRITICAL: This module prevents testing out-of-scope targets.
Every scan request passes through this validator first.

Covers:
  - Domain/wildcard matching
  - IP range checking
  - URL path scoping
  - Asset type validation
  - Rate limit enforcement
  - Legal disclaimer tracking

A professional researcher NEVER tests outside scope.
This module makes it automatic.
"""

import re
import time
import socket
import ipaddress
import threading
from urllib.parse import urlparse
from datetime import datetime
from fnmatch import fnmatch


class ScopeValidator:
    """
    Legal protection engine.
    All scan requests must be validated here first.
    """

    # Absolute never-scan list (even if someone adds to scope)
    HARDCODED_EXCLUSIONS = [
        "*.gov",
        "*.mil",
        "*.edu",
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "facebook.com",
        "cloudflare.com",
    ]

    # Private/reserved IP ranges (never scan unless explicitly in scope)
    PRIVATE_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
    ]

    # Rate limits per target (requests per second)
    DEFAULT_RATE_LIMIT = 10
    MAX_RATE_LIMIT     = 50

    def __init__(self, program=None, scope_items=None, custom_scope=None):
        """
        program:      Bug bounty program dict
        scope_items:  List of scope dicts from database
        custom_scope: Manual list of allowed targets (for local testing)
        """
        self.program      = program or {}
        self.scope_items  = scope_items or []
        self.custom_scope = custom_scope or []

        # Rate limiting state
        self._request_times = {}
        self._lock = threading.Lock()

        # Stats
        self.stats = {
            "allowed":   0,
            "blocked":   0,
            "rate_limited": 0,
        }

    def is_in_scope(self, url: str) -> tuple:
        """
        Main validation method.
        Returns (is_allowed: bool, reason: str)
        """
        # Parse URL
        try:
            parsed = urlparse(url if "://" in url else "http://" + url)
            host   = parsed.hostname or ""
            path   = parsed.path or "/"
        except Exception:
            return False, "Invalid URL"

        # 1. Check hardcoded exclusions
        for excluded in self.HARDCODED_EXCLUSIONS:
            if fnmatch(host, excluded) or fnmatch(host, excluded.lstrip("*.")):
                self.stats["blocked"] += 1
                return False, f"Hardcoded exclusion: {excluded}"

        # 2. Custom scope (local testing / lab)
        if self.custom_scope:
            for allowed in self.custom_scope:
                if self._matches_target(host, allowed):
                    self.stats["allowed"] += 1
                    return True, f"Custom scope: {allowed}"
            self.stats["blocked"] += 1
            return False, f"{host} not in custom scope"

        # 3. No program defined — only allow if custom scope
        if not self.scope_items and not self.custom_scope:
            self.stats["blocked"] += 1
            return False, "No scope defined. Set program scope or custom_scope."

        # 4. Check out-of-scope FIRST (takes priority)
        for item in self.scope_items:
            if item.get("in_scope", True):
                continue
            target = item.get("target", "")
            if self._matches_target(host, target):
                self.stats["blocked"] += 1
                return False, f"Explicitly out of scope: {target}"

        # 5. Check in-scope items
        for item in self.scope_items:
            if not item.get("in_scope", True):
                continue
            if not item.get("eligible_for_bounty", True):
                continue

            target   = item.get("target", "")
            asset_type = item.get("asset_type", "url")

            if asset_type in ["url", "domain", "wildcard"]:
                if self._matches_target(host, target):
                    # Check path restrictions if any
                    instruction = item.get("instruction", "")
                    if instruction and "path:" in instruction.lower():
                        allowed_path = instruction.split("path:")[-1].strip()
                        if not path.startswith(allowed_path):
                            continue

                    self.stats["allowed"] += 1
                    return True, f"In scope: {target}"

            elif asset_type == "ip_address":
                try:
                    if self._ip_in_range(host, target):
                        self.stats["allowed"] += 1
                        return True, f"IP in scope: {target}"
                except Exception:
                    pass

            elif asset_type == "cidr":
                try:
                    if self._ip_in_cidr(host, target):
                        self.stats["allowed"] += 1
                        return True, f"CIDR in scope: {target}"
                except Exception:
                    pass

        self.stats["blocked"] += 1
        return False, f"{host} not found in any scope item"

    def is_private_ip(self, host: str) -> bool:
        """Check if host resolves to private IP."""
        try:
            ip = socket.gethostbyname(host)
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.PRIVATE_RANGES:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
        except Exception:
            pass
        return False

    def check_rate_limit(self, host: str) -> bool:
        """
        Enforce rate limiting per target.
        Returns True if request is allowed, False if rate limited.
        """
        with self._lock:
            now = time.time()
            times = self._request_times.get(host, [])

            # Keep only last 1 second of requests
            times = [t for t in times if now - t < 1.0]

            if len(times) >= self.DEFAULT_RATE_LIMIT:
                self.stats["rate_limited"] += 1
                return False

            times.append(now)
            self._request_times[host] = times
            return True

    def validate_and_rate_limit(self, url: str) -> tuple:
        """Combined scope + rate limit check."""
        allowed, reason = self.is_in_scope(url)
        if not allowed:
            return False, reason

        try:
            host = urlparse(url).hostname
            if not self.check_rate_limit(host):
                return False, f"Rate limited: max {self.DEFAULT_RATE_LIMIT} req/s"
        except Exception:
            pass

        return True, "OK"

    def add_custom_scope(self, target: str):
        """Add a target to custom scope."""
        self.custom_scope.append(target)

    def get_stats(self) -> dict:
        return dict(self.stats)

    def generate_legal_disclaimer(self) -> str:
        """Generate legal disclaimer for scan report."""
        program_name = self.program.get("name", "this program")
        return f"""
LEGAL DISCLAIMER
═══════════════════════════════════════════════════════════
This security assessment was conducted with explicit authorization
from {program_name} under their public bug bounty program.

All testing was performed:
  ✓ Within defined scope boundaries
  ✓ With rate limiting to prevent service disruption
  ✓ In accordance with program policy
  ✓ Without accessing, modifying, or deleting user data
  ✓ Without performing denial-of-service attacks
  ✓ Without social engineering attacks on employees

Scope validated by AmonStrike ScopeValidator v2.0
Scan performed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

For questions: security@[your-email].com
═══════════════════════════════════════════════════════════
"""

    # ── Private helpers ───────────────────────────────────────

    def _matches_target(self, host: str, target: str) -> bool:
        """Match host against scope target (supports wildcards)."""
        host   = host.lower().rstrip(".")
        target = target.lower().rstrip(".")

        # Exact match
        if host == target:
            return True

        # Wildcard match (*.example.com)
        if target.startswith("*."):
            base = target[2:]
            return host == base or host.endswith("." + base)

        # Reverse wildcard (example.*)
        if "*" in target:
            return fnmatch(host, target)

        # Subdomain match (example.com matches api.example.com)
        if host.endswith("." + target):
            return True

        return False

    def _ip_in_range(self, host: str, target_ip: str) -> bool:
        """Check if host resolves to target IP."""
        try:
            ip = socket.gethostbyname(host)
            return ip == target_ip
        except Exception:
            return host == target_ip

    def _ip_in_cidr(self, host: str, cidr: str) -> bool:
        """Check if host is in CIDR range."""
        try:
            ip = socket.gethostbyname(host)
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    print("\n=== SCOPE VALIDATOR REGRESSION TESTS ===")
    passed = failed = 0

    # Test with custom scope (lab testing mode)
    lab_validator = ScopeValidator(custom_scope=[
        "192.168.178.149",
        "*.testco.com",
        "testphp.vulnweb.com",
    ])

    # Test with program scope
    prog_validator = ScopeValidator(
        program={"name":"TestCo Bug Bounty"},
        scope_items=[
            {"asset_type":"url","target":"*.testco.com","in_scope":True,"eligible_for_bounty":True},
            {"asset_type":"url","target":"api.testco.com","in_scope":True,"eligible_for_bounty":True},
            {"asset_type":"url","target":"internal.testco.com","in_scope":False,"eligible_for_bounty":False},
        ]
    )

    tests = [
        # Lab scope tests
        ("Lab: IP address in scope",
         lambda: lab_validator.is_in_scope("http://192.168.178.149/dvwa")[0] == True),
        ("Lab: wildcard subdomain in scope",
         lambda: lab_validator.is_in_scope("http://api.testco.com")[0] == True),
        ("Lab: vulnweb in scope",
         lambda: lab_validator.is_in_scope("http://testphp.vulnweb.com")[0] == True),
        ("Lab: out-of-scope rejected",
         lambda: lab_validator.is_in_scope("http://google.com")[0] == False),

        # Program scope tests
        ("Prog: wildcard match works",
         lambda: prog_validator.is_in_scope("http://www.testco.com")[0] == True),
        ("Prog: specific subdomain match",
         lambda: prog_validator.is_in_scope("http://api.testco.com")[0] == True),
        ("Prog: deep subdomain match",
         lambda: prog_validator.is_in_scope("http://staging.api.testco.com")[0] == True),
        ("Prog: out-of-scope domain rejected",
         lambda: prog_validator.is_in_scope("http://evil.com")[0] == False),
        ("Prog: internal.testco.com out of scope",
         lambda: prog_validator.is_in_scope("http://internal.testco.com")[0] == False),

        # Hardcoded exclusions
        ("Hardcoded: gov domain rejected",
         lambda: prog_validator.is_in_scope("http://whitehouse.gov")[0] == False),
        ("Hardcoded: mil domain rejected",
         lambda: prog_validator.is_in_scope("http://army.mil")[0] == False),

        # Rate limiting
        ("Rate limit: first request allowed",
         lambda: lab_validator.check_rate_limit("testco.com") == True),
        ("Rate limit: tracks request counts",
         lambda: (
             [lab_validator.check_rate_limit("ratelimit.com") for _ in range(15)],
             lab_validator.stats["rate_limited"] > 0
         )[1]),

        # Stats tracking
        ("Stats: allowed count increments",
         lambda: lab_validator.stats["allowed"] > 0),
        ("Stats: blocked count increments",
         lambda: lab_validator.stats["blocked"] > 0),

        # Disclaimer generation
        ("Legal disclaimer generated",
         lambda: "LEGAL DISCLAIMER" in prog_validator.generate_legal_disclaimer()),

        # Edge cases
        ("Empty URL handled",
         lambda: lab_validator.is_in_scope("")[0] == False),
        ("URL without scheme handled",
         lambda: lab_validator.is_in_scope("192.168.178.149")[0] == True),
    ]

    for name, fn in tests:
        try:
            result = fn()
            if result:
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


def run_stress_tests():
    import threading
    print("\n=== SCOPE VALIDATOR STRESS TESTS ===")
    passed = failed = 0

    validator = ScopeValidator(custom_scope=["*.test.com","10.0.0.0/8"])

    tests = [
        ("10000 scope checks without crash",
         lambda: all(
             isinstance(validator.is_in_scope(f"http://sub{i}.test.com"), tuple)
             for i in range(10000)
         )),

        ("Concurrent scope checks thread-safe",
         lambda: _stress_concurrent(validator)),

        ("Rate limit resets after 1 second",
         lambda: (
             [validator.check_rate_limit("reset.com") for _ in range(15)],
             time.sleep(1.1),
             validator.check_rate_limit("reset.com")
         )[2]),

        ("Long hostname handled",
         lambda: isinstance(
             validator.is_in_scope("http://" + "a"*200 + ".test.com"),
             tuple
         )),

        ("Special chars in URL",
         lambda: isinstance(
             validator.is_in_scope("http://test.com/path?id=1' OR 1=1--"),
             tuple
         )),
    ]

    for name, fn in tests:
        try:
            result = fn()
            if result:
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


def _stress_concurrent(validator):
    errors = []
    def worker():
        try:
            for i in range(100):
                validator.is_in_scope(f"http://sub{i}.test.com")
                validator.check_rate_limit(f"host{i}.com")
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    return len(errors) == 0


if __name__ == "__main__":
    rp, rf = run_regression_tests()
    sp, sf = run_stress_tests()
    print(f"\nTOTAL: {rp+sp} passed  {rf+sf} failed")
    import sys; sys.exit(0 if rf+sf==0 else 1)
