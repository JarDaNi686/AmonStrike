"""AmonStrike — CSP Evaluation Module"""
import re
from .base import BaseModule

UNSAFE_DIRECTIVES = [
    ("unsafe-inline", "HIGH",   "Allows inline scripts — XSS not mitigated"),
    ("unsafe-eval",   "HIGH",   "Allows eval() — XSS escalation possible"),
    ("*",             "HIGH",   "Wildcard source allows loading from any domain"),
    ("data:",         "MEDIUM", "data: URI allows base64 XSS payloads"),
    ("http:",         "MEDIUM", "Allows loading from insecure HTTP origins"),
]

BYPASSABLE_DOMAINS = [
    ("ajax.googleapis.com",    "MEDIUM", "Google JSONP bypass possible"),
    ("cdn.jsdelivr.net",       "MEDIUM", "CDN with arbitrary user packages"),
    ("unpkg.com",              "MEDIUM", "npm CDN — host arbitrary packages"),
    ("cdnjs.cloudflare.com",   "LOW",    "Many library versions, some vulnerable"),
]

class CspBypassModule(BaseModule):
    NAME        = "csp_bypass"
    DESCRIPTION = "CSP — evaluate policy, find bypasses, missing directives"

    def run(self):
        self.log("Evaluating Content Security Policy...")
        r = self.get("")
        if not r: return self.result()

        csp = (r.headers.get("Content-Security-Policy","") or
               r.headers.get("X-Content-Security-Policy",""))

        if not csp:
            self.add_finding(
                title       = "No Content Security Policy",
                severity    = "MEDIUM",
                description = "No CSP header found. XSS attacks can execute without restriction.",
                evidence    = "Content-Security-Policy: MISSING",
                remediation = "Implement a strict CSP. Start with: default-src \'self\'; script-src \'self\'",
                url=self.url, cve="CWE-1021",
            )
            return self.result()

        self.info["csp"] = csp

        # Check unsafe directives
        for directive, sev, desc in UNSAFE_DIRECTIVES:
            if directive in csp:
                self.add_finding(
                    title       = f"CSP Weakness — \'{directive}\' Directive",
                    severity    = sev,
                    description = f"CSP contains \'{directive}\'. {desc}",
                    evidence    = f"CSP: {csp[:300]}\nProblematic: {directive}",
                    remediation = f"Remove \'{directive}\' from CSP. Use nonces or hashes instead.",
                    url=self.url, cve="CWE-1021",
                )

        # Check bypassable CDN domains
        for domain, sev, desc in BYPASSABLE_DOMAINS:
            if domain in csp:
                self.add_finding(
                    title       = f"CSP Bypass — Whitelisted Bypassable Domain: {domain}",
                    severity    = sev,
                    description = f"{domain} in CSP. {desc}",
                    evidence    = f"Domain in CSP: {domain}\nCSP: {csp[:200]}",
                    remediation = f"Remove {domain} from CSP or use SRI hashes for specific scripts.",
                    url=self.url, cve="CWE-1021",
                )

        # Check for missing directives
        for directive in ["default-src","script-src","object-src","base-uri"]:
            if directive not in csp and "default-src" not in csp:
                self.add_finding(
                    title       = f"CSP Missing Directive: {directive}",
                    severity    = "LOW",
                    description = f"CSP missing \'{directive}\' falls back to permissive default.",
                    evidence    = f"Missing: {directive}\nCSP: {csp[:200]}",
                    remediation = f"Add \'{directive} \'self\'\' to CSP.",
                    url=self.url, cve="CWE-1021",
                )
        return self.result()
