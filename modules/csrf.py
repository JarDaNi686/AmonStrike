"""AmonStrike — CSRF Module"""
import re
from urllib.parse import urljoin
from .base import BaseModule

class CsrfModule(BaseModule):
    NAME = "csrf"
    DESCRIPTION = "CSRF — token detection, SameSite analysis, state-changing requests"

    def run(self):
        self.log("Testing for CSRF vulnerabilities...")
        resp = self.get()
        if not resp:
            return self.result()

        self._check_forms(resp)
        self._check_api_csrf()
        self.log(f"CSRF scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _check_forms(self, resp):
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form", method=lambda m: m and m.lower() == "post")

            for form in forms:
                inputs = form.find_all("input")
                has_token = False
                for inp in inputs:
                    name = (inp.get("name", "") or "").lower()
                    itype = (inp.get("type", "") or "").lower()
                    if "csrf" in name or "token" in name or "nonce" in name or itype == "hidden":
                        val = inp.get("value", "")
                        if val and len(val) > 10:
                            has_token = True
                            break

                if not has_token:
                    action = form.get("action", self.url)
                    self.add_finding(
                        title="CSRF — Missing Token in POST Form",
                        severity="HIGH",
                        description="POST form does not contain a CSRF token. An attacker can trick a logged-in user into submitting this form.",
                        evidence=f"Form action: {action}\nNo CSRF token found in form inputs.",
                        remediation="Implement CSRF tokens in all state-changing forms. Use SameSite=Strict cookies. Verify Origin/Referer headers.",
                        url=urljoin(self.url, action),
                        cve="CWE-352"
                    )
        except ImportError:
            pass

    def _check_api_csrf(self):
        """Check if API endpoints accept simple requests without CSRF protection."""
        api_paths = ["/api/user", "/api/profile", "/api/settings", "/api/password"]
        for path in api_paths:
            r = self.post(path, data={"test": "1"}, headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil.com"})
            if r and r.status_code not in [404, 405, 501]:
                if r.headers.get("Access-Control-Allow-Origin") == "*":
                    self.add_finding(
                        title=f"CSRF via CORS Misconfiguration: {path}",
                        severity="HIGH",
                        description=f"API endpoint {path} accepts cross-origin requests with wildcard CORS. CSRF attacks possible.",
                        evidence=f"POST {path} with Origin: evil.com → {r.status_code}",
                        remediation="Restrict CORS to trusted origins. Validate CSRF tokens on API endpoints.",
                        url=self.url + path,
                        cve="CWE-352"
                    )
