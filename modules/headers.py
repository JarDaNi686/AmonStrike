"""
AmonStrike — Security Headers Module
Checks all OWASP recommended security headers.
"""

from .base import BaseModule


class HeadersModule(BaseModule):
    NAME        = "headers"
    DESCRIPTION = "Security headers analysis — CSP, HSTS, X-Frame, etc."

    REQUIRED_HEADERS = {
        "Content-Security-Policy": {
            "severity": "HIGH",
            "desc": "CSP prevents XSS, clickjacking, and data injection attacks.",
            "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        },
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "desc": "HSTS forces HTTPS and prevents protocol downgrade attacks.",
            "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "desc": "Prevents MIME-type sniffing attacks.",
            "remediation": "Add: X-Content-Type-Options: nosniff",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "desc": "Prevents clickjacking attacks.",
            "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "desc": "Controls referrer information sent with requests.",
            "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "desc": "Controls browser features and APIs.",
            "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "desc": "Legacy XSS filter for older browsers.",
            "remediation": "Add: X-XSS-Protection: 1; mode=block",
        },
    }

    def run(self):
        self.log("Analyzing security headers...")

        resp = self.get()
        if not resp:
            return self.result()

        headers = resp.headers
        self.info["all_headers"] = dict(headers)
        missing = []
        present = []

        for header, meta in self.REQUIRED_HEADERS.items():
            if header.lower() not in {k.lower() for k in headers.keys()}:
                missing.append(header)
                self.add_finding(
                    title=f"Missing Security Header: {header}",
                    severity=meta["severity"],
                    description=meta["desc"],
                    evidence=f"Header '{header}' not found in response.",
                    remediation=meta["remediation"],
                    url=resp.url
                )
            else:
                val = headers.get(header, "")
                present.append(f"{header}: {val}")

                # Check CSP quality
                if header == "Content-Security-Policy":
                    self._analyze_csp(val, resp.url)

                # Check HSTS quality
                if header == "Strict-Transport-Security":
                    self._analyze_hsts(val, resp.url)

        self.info["missing_headers"] = missing
        self.info["present_headers"] = present
        self.log(f"Headers: {len(present)} present, {len(missing)} missing", "+")
        return self.result()

    def _analyze_csp(self, csp_value, url):
        """Analyze CSP policy quality."""
        issues = []

        if "unsafe-inline" in csp_value:
            issues.append("'unsafe-inline' allows inline scripts — defeats XSS protection")
        if "unsafe-eval" in csp_value:
            issues.append("'unsafe-eval' allows eval() — dangerous for XSS")
        if "*" in csp_value:
            issues.append("Wildcard (*) in CSP allows any source")
        if "default-src" not in csp_value and "script-src" not in csp_value:
            issues.append("No script-src or default-src directive")

        if issues:
            self.add_finding(
                title="Weak Content-Security-Policy",
                severity="MEDIUM",
                description="CSP is present but contains weak directives that reduce its effectiveness.",
                evidence=f"CSP: {csp_value}\nIssues:\n" + "\n".join(f"- {i}" for i in issues),
                remediation="Tighten CSP: remove 'unsafe-inline', 'unsafe-eval', and wildcards. Use nonces or hashes for inline scripts.",
                url=url
            )

    def _analyze_hsts(self, hsts_value, url):
        """Analyze HSTS policy."""
        if "max-age=0" in hsts_value:
            self.add_finding(
                title="HSTS Disabled (max-age=0)",
                severity="HIGH",
                description="HSTS is present but max-age=0 effectively disables it.",
                evidence=f"Strict-Transport-Security: {hsts_value}",
                remediation="Set max-age to at least 31536000 (1 year).",
                url=url
            )
        elif "includeSubDomains" not in hsts_value:
            self.add_finding(
                title="HSTS Missing includeSubDomains",
                severity="LOW",
                description="HSTS does not include subdomains, leaving them unprotected.",
                evidence=f"Strict-Transport-Security: {hsts_value}",
                remediation="Add includeSubDomains to HSTS header.",
                url=url
            )
