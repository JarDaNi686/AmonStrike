"""AmonStrike — Account Takeover Module"""
import re, hashlib, time
from .base import BaseModule

class AccountTakeoverModule(BaseModule):
    NAME        = "account_takeover"
    DESCRIPTION = "ATO — password reset flaws, token prediction, host header injection"

    def run(self):
        self.log("Testing account takeover vectors...")
        self._test_password_reset_host_injection()
        self._test_weak_reset_tokens()
        self._test_reset_token_in_referrer()
        self._test_user_enumeration()
        self.log(f"ATO complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_password_reset_host_injection(self):
        """Host header injection in password reset email."""
        for path in ["/api/forgot-password","/api/password/reset","/forgot-password"]:
            r = self.get(path)
            if not r or r.status_code == 404: continue
            # Inject evil host
            r2 = self.post(path,
                json={"email":"victim@target.com","username":"admin"},
                headers={"Host":"evil.com","X-Forwarded-Host":"evil.com"},
            )
            if r2 and r2.status_code in [200,201]:
                self.add_finding(
                    title       = f"Password Reset — Host Header Injection: {path}",
                    severity    = "HIGH",
                    description = (
                        "Password reset endpoint uses Host header to build reset URL. "
                        "Injecting evil.com as Host causes reset link to point to attacker domain. "
                        "When victim clicks reset link: token sent to attacker → ATO."
                    ),
                    evidence    = f"Path: {path}\nHost header: evil.com\nResponse: {r2.status_code}",
                    remediation = "Hardcode the domain in password reset emails. Never use Host header for URL generation.",
                    url=self.url+path, cve="CWE-640",
                )

    def _test_weak_reset_tokens(self):
        """Check if reset tokens are predictable."""
        for path in ["/api/forgot-password","/api/password/reset"]:
            tokens = []
            for email in ["test1@test.com","test2@test.com","test3@test.com"]:
                r = self.post(path, json={"email":email})
                if r and r.status_code in [200,201]:
                    try:
                        data  = r.json()
                        token = data.get("token","") or data.get("reset_token","")
                        if token:
                            tokens.append(token)
                    except Exception: pass

            if tokens:
                # Token in response = already critical
                self.add_finding(
                    title       = "Password Reset Token Returned in API Response",
                    severity    = "CRITICAL",
                    description = "Reset token returned directly in API response — send to email only.",
                    evidence    = f"Token: {tokens[0][:30]}...",
                    remediation = "Never return reset tokens in API responses. Send only via email.",
                    url=self.url+path, cve="CWE-640",
                )
            elif len(tokens) >= 3:
                # Check if sequential/predictable
                try:
                    ints = [int(t, 16) if all(c in "0123456789abcdef" for c in t) else int(t) for t in tokens]
                    diffs = [ints[i+1]-ints[i] for i in range(len(ints)-1)]
                    if len(set(diffs)) == 1:
                        self.add_finding(
                            title="Predictable Password Reset Token",
                            severity="CRITICAL",
                            description="Reset tokens are sequential/predictable.",
                            evidence=f"Tokens: {tokens}\nDifferences: {diffs}",
                            remediation="Use cryptographically secure random token generation (secrets.token_hex(32)).",
                            url=self.url+path, cve="CWE-330",
                        )
                except Exception: pass

    def _test_reset_token_in_referrer(self):
        """Password reset token leaks via Referer header."""
        # Can't directly test this but flag the pattern
        for path in ["/api/forgot-password","/api/password/reset","/reset-password"]:
            r = self.get(path)
            if not r or r.status_code == 404: continue
            if "token=" in r.url:
                self.add_finding(
                    title="Password Reset Token in URL — Leaks via Referer",
                    severity="HIGH",
                    description="Reset token in URL leaks via Referer header to analytics/CDN.",
                    evidence=f"URL contains token: {r.url}",
                    remediation="Pass reset tokens via POST body or signed JWT, not URL query string.",
                    url=self.url+path, cve="CWE-598",
                )

    def _test_user_enumeration(self):
        """Check if login/reset reveals valid usernames."""
        for path in ["/api/login","/api/forgot-password","/api/auth"]:
            r_valid = self.post(path, json={"username":"admin","email":"admin@"+self.parsed.hostname,"password":"wrong"})
            r_invalid = self.post(path, json={"username":"noexist_xyz_abc","email":"noexist@fake.xyz","password":"wrong"})
            if not r_valid or not r_invalid: continue
            # Different responses = enumeration
            if r_valid.status_code != r_invalid.status_code:
                self.add_finding(
                    title=f"User Enumeration — Different Responses at {path}",
                    severity="MEDIUM",
                    description="Different status codes for valid vs invalid usernames enable enumeration.",
                    evidence=f"Valid user → {r_valid.status_code}\nInvalid user → {r_invalid.status_code}",
                    remediation="Return identical responses for valid and invalid usernames.",
                    url=self.url+path, cve="CWE-203",
                )
