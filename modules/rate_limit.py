"""
AmonStrike — Rate Limit Detection & Bypass Module
Missing rate limits = brute force, credential stuffing, OTP bypass.
"""
import time
import threading
from .base import BaseModule


class RateLimitModule(BaseModule):
    NAME        = "rate_limit"
    DESCRIPTION = "Rate limit testing — login, OTP, API endpoints"

    BYPASS_HEADERS = [
        {"X-Forwarded-For":  "1.2.3.{}"},
        {"X-Real-IP":        "1.2.3.{}"},
        {"X-Originating-IP": "1.2.3.{}"},
        {"CF-Connecting-IP": "1.2.3.{}"},
        {"True-Client-IP":   "1.2.3.{}"},
    ]

    def run(self):
        self.log("Testing rate limiting...")

        self._test_login_rate_limit()
        self._test_otp_rate_limit()
        self._test_api_rate_limit()
        self._test_bypass_techniques()

        self.log(f"Rate limit complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_login_rate_limit(self):
        """Check if login endpoint rate-limits failed attempts."""
        login_paths = ["/api/login","/api/auth","/login","/api/v1/auth","/auth/login"]
        for path in login_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            codes = []
            for i in range(15):
                r2 = self.post(path, json={
                    "username": "admin",
                    "password": f"wrongpass_{i}",
                    "email":    "admin@test.com",
                })
                codes.append(r2.status_code if r2 else 0)

            # Check if all returned same status (no rate limiting)
            if codes and all(c == codes[0] for c in codes) and codes[0] not in [429,403]:
                self.add_finding(
                    title       = f"No Rate Limiting on Login Endpoint: {path}",
                    severity    = "HIGH",
                    description = (
                        f"Login endpoint {path} does not rate-limit failed attempts. "
                        f"15 consecutive failed attempts returned status {codes[0]} each time. "
                        f"Brute force and credential stuffing attacks possible."
                    ),
                    evidence    = f"15 requests to {path}\nAll returned: {codes[0]}\nNo 429/lockout",
                    remediation = "Implement rate limiting (5 attempts/min). Add CAPTCHA after 3 failures. Implement account lockout.",
                    url         = self.url + path,
                    cve         = "CWE-307",
                )
                break

    def _test_otp_rate_limit(self):
        """Check OTP/2FA rate limiting."""
        otp_paths = [
            "/api/otp/verify","/api/2fa/verify","/api/auth/otp","/verify-otp",
        ]
        for path in otp_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            codes = []
            for i in range(20):
                code = str(i).zfill(6)
                r2 = self.post(path, json={"otp": code, "code": code})
                codes.append(r2.status_code if r2 else 0)

            if codes and all(c not in [429,403,423] for c in codes):
                self.add_finding(
                    title       = f"No Rate Limiting on OTP Endpoint: {path}",
                    severity    = "CRITICAL",
                    description = (
                        f"OTP/2FA endpoint {path} does not rate-limit verification attempts. "
                        f"6-digit OTP has only 1,000,000 possible values — can be brute-forced "
                        f"in minutes without rate limiting."
                    ),
                    evidence    = f"20 OTP guesses, none blocked. All status codes: {set(codes)}",
                    remediation = "Limit OTP to 3-5 attempts. Expire OTP after 5 minutes. Lock account after max attempts.",
                    url         = self.url + path,
                    cve         = "CWE-307",
                )

    def _test_api_rate_limit(self):
        """Test if API endpoints have rate limiting."""
        api_paths = ["/api/", "/api/v1/", "/api/v1/users", "/api/search"]
        for path in api_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Send 50 rapid requests
            codes = []
            start = time.time()
            for _ in range(50):
                r2 = self.session.get(self.url + path, timeout=3, verify=False)
                codes.append(r2.status_code if r2 else 0)

            elapsed = time.time() - start
            hit_limit = any(c == 429 for c in codes)

            if not hit_limit and 200 in codes:
                self.add_finding(
                    title       = f"No API Rate Limiting: {path}",
                    severity    = "MEDIUM",
                    description = f"API endpoint {path} served 50 requests in {elapsed:.1f}s without rate limiting.",
                    evidence    = f"50 requests in {elapsed:.1f}s, all successful. No 429 received.",
                    remediation = "Implement API rate limiting (e.g., 100 req/min per IP/token).",
                    url         = self.url + path,
                    cve         = "CWE-770",
                )
                break

    def _test_bypass_techniques(self):
        """Test if rate limits can be bypassed via IP spoofing headers."""
        login_path = None
        for path in ["/api/login","/api/auth","/login"]:
            r = self.get(path)
            if r and r.status_code != 404:
                login_path = path
                break

        if not login_path:
            return

        # Try to trigger rate limit first
        for _ in range(20):
            self.post(login_path, json={"username":"a","password":"b"})

        # Now try bypass with spoofed IP
        for hdr_template in self.BYPASS_HEADERS:
            hdr = {k: v.format(42) for k, v in hdr_template.items()}
            r = self.post(
                login_path,
                json={"username":"a","password":"b"},
                headers=hdr,
            )
            if r and r.status_code not in [429,403,423]:
                hdr_name = list(hdr.keys())[0]
                self.add_finding(
                    title       = f"Rate Limit Bypass via {hdr_name} Header",
                    severity    = "HIGH",
                    description = f"Rate limit bypassed by spoofing {hdr_name} header with a different IP.",
                    evidence    = f"Header: {hdr}\nStatus after rate limit: {r.status_code}",
                    remediation = "Do not use X-Forwarded-For for rate limiting. Use authenticated user ID or server-side session.",
                    url         = self.url + login_path,
                    cve         = "CWE-307",
                )
                break
