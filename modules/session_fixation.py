"""AmonStrike — Session Fixation Module"""
from .base import BaseModule

class SessionFixationModule(BaseModule):
    NAME        = "session_fixation"
    DESCRIPTION = "Session fixation — pre-login token reuse, prediction"

    def run(self):
        self.log("Testing session fixation...")
        self._test_session_fixation()
        self._test_predictable_tokens()
        return self.result()

    def _test_session_fixation(self):
        """Check if pre-login session ID persists after login."""
        # Get session before login
        r1 = self.get("")
        if not r1: return
        pre_cookies = dict(r1.cookies)
        if not pre_cookies: return

        # Attempt login
        for path in ["/api/login","/login","/api/auth"]:
            r2 = self.post(path, json={"username":"test","password":"test"},
                          cookies=pre_cookies)
            if not r2 or r2.status_code not in [200,201]: continue

            post_cookies = dict(r2.cookies)
            # Check if session IDs stayed the same
            for key in pre_cookies:
                if key in post_cookies and pre_cookies[key] == post_cookies[key]:
                    self.add_finding(
                        title       = f"Session Fixation — Cookie \'{key}\' Not Rotated on Login",
                        severity    = "HIGH",
                        description = (
                            f"Session cookie \'{key}\' is not regenerated after login. "
                            "An attacker who sets a known session ID before the victim logs in "
                            "can hijack their authenticated session."
                        ),
                        evidence    = f"Cookie \'{key}\' value same before and after login: {pre_cookies[key][:20]}...",
                        remediation = "Regenerate all session tokens on login. Invalidate pre-auth session.",
                        url=self.url+path, cve="CWE-384",
                    )
                    return

    def _test_predictable_tokens(self):
        """Check for predictable/sequential session tokens."""
        tokens = []
        for _ in range(5):
            r = self.get("")
            if r:
                for k,v in r.cookies.items():
                    if any(s in k.lower() for s in ["session","sess","token","sid","auth"]):
                        tokens.append(v)
        if len(tokens) >= 3:
            lengths = [len(t) for t in tokens]
            if max(lengths) < 16:
                self.add_finding(
                    title       = "Weak Session Token — Too Short",
                    severity    = "HIGH",
                    description = f"Session tokens are only {max(lengths)} characters — brute-forceable.",
                    evidence    = f"Token lengths: {lengths}",
                    remediation = "Use cryptographically random tokens of at least 128 bits (32 hex chars).",
                    url=self.url, cve="CWE-330",
                )
