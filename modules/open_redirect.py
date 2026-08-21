"""AmonStrike — Open Redirect Module (Real-Target Edition)"""
import re
from .base import BaseModule
from urllib.parse import urlparse, urljoin

REDIRECT_PARAMS = [
    "redirect","redirect_uri","redirect_url","return","return_url",
    "returnTo","return_to","next","next_url","goto","go","url",
    "destination","dest","target","to","continue","forward","ref",
    "location","back","redir","rurl","origin","callback","out","link",
]

PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com?legitimate.com",
    "https://legitimate.com.evil.com",
    "javascript:alert(1)",
    "//evil.com/%2f..",
    "%09//evil.com",
    "%0d%0a//evil.com",
]

EVIL = "evil.com"


class OpenRedirectModule(BaseModule):
    NAME        = "open_redirect"
    DESCRIPTION = "Open redirect — URL params, OAuth, spider-based discovery"

    def run(self):
        self.log("Testing open redirects...")
        self._spider_and_test()
        self._test_oauth_endpoints()
        self.log(f"Open redirect complete — {len(self.findings)} findings", "+")
        return self.result()

    def _spider_and_test(self):
        # Test base URL params
        from urllib.parse import parse_qs
        p = urlparse(self.url)
        if p.query:
            for param, vals in parse_qs(p.query).items():
                if any(kw in param.lower() for kw in ["redirect","url","next","return","goto","dest"]):
                    self._test_param(self.url.split("?")[0], param, vals[0])

        # Spider for redirect params
        r = self.get("")
        if not r:
            return

        links = re.findall(r'href=["\']([^"\'#]+)["\']', r.text)
        links += list(getattr(self, "extra_endpoints", []))[:10]

        for link in links[:30]:
            abs_url = link if link.startswith("http") else urljoin(self.url, link)
            if self.parsed.netloc not in abs_url:
                continue
            p2 = urlparse(abs_url)
            from urllib.parse import parse_qs as _pq
            for param, vals in _pq(p2.query).items():
                if any(kw in param.lower() for kw in REDIRECT_PARAMS[:10]):
                    self._test_param(abs_url.split("?")[0], param, vals[0])
                    if self.findings:
                        return

        # Try common redirect params on base URL
        for param in REDIRECT_PARAMS[:8]:
            self._test_param(self.url.split("?")[0], param, "https://test.com")
            if self.findings:
                return

    def _test_param(self, base_url: str, param: str, orig_val: str):
        for payload in PAYLOADS[:5]:
            r = self.get(base_url, params={param: payload}, allow_redirects=False)
            if not r:
                continue
            if r.status_code in [301,302,303,307,308]:
                loc = r.headers.get("Location","")
                if EVIL in loc or "javascript:" in loc.lower():
                    oauth_path = any(p in base_url.lower() for p in
                                    ["oauth","auth","login","sso","callback"])
                    self.add_finding(
                        title       = f"Open Redirect via '{param}' — {'OAuth/Auth endpoint' if oauth_path else 'URL parameter'}",
                        severity    = "CRITICAL" if oauth_path else "MEDIUM",
                        description = (
                            f"Parameter '{param}' redirects to attacker-controlled URL. "
                            + ("On an auth endpoint this enables OAuth token theft and account takeover."
                               if oauth_path else "")
                        ),
                        evidence    = (
                            f"URL: {base_url}?{param}={payload}\n"
                            f"Status: {r.status_code}\n"
                            f"Location: {loc}"
                        ),
                        remediation = "Validate redirects against explicit allowlist of trusted domains.",
                        url         = base_url,
                        parameter   = param,
                        payload     = payload,
                        cve         = "CWE-601",
                    )
                    return

    def _test_oauth_endpoints(self):
        for path in ["/oauth/authorize","/auth/oauth","/oauth2/authorize",
                     "/connect/authorize","/api/oauth/authorize","/callback"]:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue
            for payload in PAYLOADS[:3]:
                params = {"response_type":"code","client_id":"test",
                         "redirect_uri":payload,"scope":"openid email"}
                r2 = self.get(path, params=params, allow_redirects=False)
                if r2 and r2.status_code in [301,302]:
                    loc = r2.headers.get("Location","")
                    if EVIL in loc:
                        self.add_finding(
                            title       = f"OAuth redirect_uri Open Redirect — Account Takeover Risk",
                            severity    = "CRITICAL",
                            description = (
                                f"OAuth endpoint {path} accepts arbitrary redirect_uri. "
                                "Attacker can steal authorization codes via crafted link."
                            ),
                            evidence    = f"Path: {path}\nredirect_uri: {payload}\nLocation: {loc}",
                            remediation = "Strictly validate redirect_uri against registered values.",
                            url         = self.url + path,
                            parameter   = "redirect_uri",
                            payload     = payload,
                            cve         = "CWE-601",
                        )
                        return
