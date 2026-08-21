"""
AmonStrike — CORS Module (Real-Target Edition)
Tests all discovered API endpoints, not just homepage.
"""
import re
from .base import BaseModule
from urllib.parse import urljoin

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://evil.trusted-domain.com",
]


class CorsModule(BaseModule):
    NAME        = "cors"
    DESCRIPTION = "CORS — API endpoints, credentialed requests, origin reflection"

    def run(self):
        self.log("Testing CORS configuration...")
        endpoints = self._collect_endpoints()
        self.log(f"Testing {len(endpoints)} endpoints for CORS", "i")

        for ep in endpoints:
            self._test_cors(ep)

        self.log(f"CORS scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _collect_endpoints(self) -> list:
        endpoints = set([self.url])

        r = self.get("")
        if r:
            # API paths from JS
            for m in re.finditer(r'["\'](/(?:api|v\d|rest|graphql)[^\s"\'<>?#]*)["\']', r.text):
                ep = urljoin(self.url, m.group(1))
                endpoints.add(ep)

            # Links
            for link in re.findall(r'href=["\']([^"\'#]+)["\']', r.text):
                abs_url = link if link.startswith("http") else urljoin(self.url, link)
                if self.parsed.netloc in abs_url:
                    endpoints.add(abs_url)

        # Common API paths
        for path in ["/api/","/api/v1/","/api/v2/","/api/data","/api/user",
                     "/api/me","/api/users","/api/account","/api/settings",
                     "/api/profile","/rest/","/graphql"]:
            endpoints.add(self.url.rstrip("/") + path)

        # Recon endpoints
        for ep in getattr(self, "extra_endpoints", [])[:15]:
            endpoints.add(ep)

        return list(endpoints)[:25]

    def _test_cors(self, url: str):
        for origin in EVIL_ORIGINS:
            r = self.get(url.replace(self.url,"") or "",
                        headers={"Origin": origin},
                        allow_redirects=True)
            if not r:
                continue

            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","").lower()
            achd = r.headers.get("Access-Control-Allow-Headers","")

            # Critical: reflects arbitrary origin + allows credentials
            if (acao == origin or acao == "*") and acac == "true":
                self.add_finding(
                    title       = f"CORS Misconfiguration — Credentialed Requests Allowed: {url}",
                    severity    = "CRITICAL",
                    description = (
                        f"The endpoint reflects the attacker's Origin header "
                        f"({origin}) and allows credentials. "
                        f"Any website can make authenticated requests on behalf of victims "
                        f"and read the responses, enabling account takeover and data theft."
                    ),
                    evidence    = (
                        f"URL: {url}\n"
                        f"Origin sent: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}\n"
                        f"Response: {r.text[:200]}"
                    ),
                    remediation = (
                        "1. Never reflect arbitrary Origin headers\n"
                        "2. Maintain explicit allowlist of trusted origins\n"
                        "3. Never combine Access-Control-Allow-Origin: * with credentials\n"
                        "4. Validate Origin strictly (exact match, not substring)"
                    ),
                    url         = url,
                    cve         = "CWE-942",
                )
                return

            # High: reflects arbitrary origin without credentials
            elif acao == origin:
                self.add_finding(
                    title       = f"CORS — Origin Reflection (No Credentials): {url}",
                    severity    = "HIGH",
                    description = (
                        f"Endpoint reflects the Origin header from any domain. "
                        f"While credentials are not explicitly allowed, "
                        f"this allows cross-origin reading of non-credentialed responses."
                    ),
                    evidence    = (
                        f"URL: {url}\n"
                        f"Origin: {origin}\n"
                        f"ACAO: {acao}"
                    ),
                    remediation = "Use an explicit allowlist for trusted origins.",
                    url         = url,
                    cve         = "CWE-942",
                )
                return

            # Medium: wildcard
            elif acao == "*" and len(r.text) > 50:
                self.add_finding(
                    title       = f"CORS Wildcard — Public Data Exposed: {url}",
                    severity    = "MEDIUM",
                    description = "Endpoint uses Access-Control-Allow-Origin: * allowing any website to read responses.",
                    evidence    = f"URL: {url}\nACAO: *\nResponse: {r.text[:150]}",
                    remediation = "Use explicit origin allowlist instead of wildcard.",
                    url         = url,
                    cve         = "CWE-942",
                )
                return
