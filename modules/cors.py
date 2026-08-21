"""AmonStrike — CORS Misconfiguration Module"""
from .base import BaseModule

class CorsModule(BaseModule):
    NAME = "cors"
    DESCRIPTION = "CORS misconfiguration — origin reflection, wildcard, credentials"

    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        f"https://{'{TARGET}'}",
        "null",
        "https://evil.{TARGET}",
    ]

    def run(self):
        self.log("Testing CORS configuration...")
        host = self.parsed.hostname

        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            f"https://evil.{host}",
            f"https://{host}.evil.com",
            "null",
        ]

        for origin in test_origins:
            resp = self.get(headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self.add_finding(
                    title="CORS Wildcard Origin",
                    severity="MEDIUM",
                    description="Server responds with Access-Control-Allow-Origin: * which allows any origin to make cross-origin requests.",
                    evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                    remediation="Restrict CORS to specific trusted origins. Never use wildcard with credentials.",
                    url=resp.url
                )
                break

            if acao == origin and origin != "null":
                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                self.add_finding(
                    title=f"CORS Origin Reflection {'with Credentials' if acac.lower() == 'true' else ''}",
                    severity=severity,
                    description=f"Server reflects arbitrary Origin header in ACAO response. {'Credentials are also allowed, enabling full account takeover.' if acac.lower() == 'true' else ''}",
                    evidence=f"Request Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    remediation="Validate Origin against a whitelist of trusted domains. Never reflect arbitrary origins.",
                    url=resp.url
                )

            if origin == "null" and acao == "null":
                self.add_finding(
                    title="CORS Allows null Origin",
                    severity="HIGH",
                    description="Server allows 'null' origin. Sandboxed iframes and local files can exploit this.",
                    evidence="Origin: null → Access-Control-Allow-Origin: null",
                    remediation="Never allow null as a valid CORS origin.",
                    url=resp.url
                )

        # Also test API endpoints — CORS is usually on /api/* not homepage
        import re as _re
        r0 = self.get("")
        if r0:
            # Find API paths from JS and links
            api_paths = set()
            for m in _re.finditer(r'["\'](/api/[^\s"\'<>?#]+)["\'"]', r0.text):
                api_paths.add(m.group(1))
            for m in _re.finditer(r'href=["\'"]([^"\'#]*api[^"\'#]*)["\'"]', r0.text):
                api_paths.add(m.group(1))
            # Also try common API paths
            for path in ["/api/","/api/v1/","/api/data","/api/user","/api/users","/api/me"]:
                api_paths.add(path)

            for path in list(api_paths)[:10]:
                for origin in ["https://evil.com", "null"]:
                    resp2 = self.get(path, headers={"Origin": origin})
                    if not resp2: continue
                    acao2 = resp2.headers.get("Access-Control-Allow-Origin","")
                    acac2 = resp2.headers.get("Access-Control-Allow-Credentials","")
                    if acao2 == origin or (acao2 == "*" and acac2.lower() == "true"):
                        sev = "CRITICAL" if acac2.lower() == "true" else "HIGH"
                        self.add_finding(
                            title=f"CORS Misconfiguration on {path}",
                            severity=sev,
                            description=f"API endpoint {path} reflects Origin. {'Credentials allowed → full account takeover.' if acac2.lower()=='true' else ''}",
                            evidence=f"Path: {path}\nOrigin: {origin}\nACAO: {acao2}\nACAC: {acac2}",
                            remediation="Whitelist allowed origins. Never reflect arbitrary Origin headers.",
                            url=self.url+path
                        )
                    if self.findings: break
                if self.findings: break

        self.log(f"CORS scan complete — {len(self.findings)} findings", "+")
        return self.result()
