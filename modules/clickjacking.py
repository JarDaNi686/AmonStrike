"""AmonStrike — Clickjacking Module"""
from .base import BaseModule

class ClickjackingModule(BaseModule):
    NAME        = "clickjacking"
    DESCRIPTION = "Clickjacking — X-Frame-Options, CSP frame-ancestors, UI redressing"

    def run(self):
        self.log("Testing clickjacking...")
        r = self.get("")
        if not r:
            return self.result()

        hdrs     = {k.lower(): v for k, v in r.headers.items()}
        xfo      = hdrs.get("x-frame-options","")
        csp      = hdrs.get("content-security-policy","")
        fa       = "frame-ancestors" in csp

        if not xfo and not fa:
            self.add_finding(
                title       = "Clickjacking Vulnerability — No Frame Protection",
                severity    = "MEDIUM",
                description = (
                    "The page has no X-Frame-Options or CSP frame-ancestors directive. "
                    "An attacker can embed this page in an iframe on a malicious site, "
                    "tricking users into performing actions (clicks, form submissions) "
                    "they did not intend. On login/payment pages this is CRITICAL."
                ),
                evidence    = (
                    f"X-Frame-Options: {xfo or 'MISSING'}\n"
                    f"CSP frame-ancestors: {'present' if fa else 'MISSING'}\n"
                    f"PoC: <iframe src=\"{self.url}\" width=\"500\" height=\"500\"></iframe>"
                ),
                remediation = (
                    "Add: X-Frame-Options: DENY (or SAMEORIGIN)\n"
                    "Or CSP: frame-ancestors \'none\' (stronger, preferred)."
                ),
                url         = self.url, cve="CWE-1021",
            )
        elif xfo.lower() == "allowall":
            self.add_finding(
                title       = "Clickjacking — X-Frame-Options: ALLOWALL",
                severity    = "MEDIUM",
                description = "X-Frame-Options is set to ALLOWALL, permitting all framing.",
                evidence    = f"X-Frame-Options: {xfo}",
                remediation = "Set X-Frame-Options to DENY or SAMEORIGIN.",
                url         = self.url, cve="CWE-1021",
            )
        return self.result()
