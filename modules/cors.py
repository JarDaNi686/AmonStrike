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

        self.log(f"CORS scan complete — {len(self.findings)} findings", "+")
        return self.result()
