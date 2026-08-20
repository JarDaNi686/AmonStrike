"""AmonStrike — IDOR Module"""
from urllib.parse import parse_qs, urlparse
from .base import BaseModule

class IdorModule(BaseModule):
    NAME = "idor"
    DESCRIPTION = "Insecure Direct Object Reference — ID manipulation"

    def run(self):
        self.log("Testing for IDOR vulnerabilities...")
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        id_params = {k: v[0] for k, v in params.items()
                    if any(s in k.lower() for s in ["id", "user", "account", "order", "doc", "file", "record", "uid", "pid"])}

        if not id_params:
            id_params = {"id": "1", "user_id": "1"}

        for param, orig_val in id_params.items():
            try:
                orig_int = int(orig_val)
            except ValueError:
                continue

            # Get baseline
            r_orig = self.get(params={param: orig_int})
            if not r_orig or r_orig.status_code not in [200]:
                continue

            # Test adjacent IDs
            for test_id in [orig_int - 1, orig_int + 1, orig_int + 100, 0, 1, 2]:
                if test_id == orig_int:
                    continue
                r_test = self.get(params={param: test_id})
                if r_test and r_test.status_code == 200 and len(r_test.text) > 100:
                    if r_test.text != r_orig.text:
                        self.add_finding(
                            title=f"Potential IDOR — Parameter: {param}",
                            severity="HIGH",
                            description=f"Parameter '{param}' appears to directly reference objects. Changing ID from {orig_int} to {test_id} returns different data without authorization check.",
                            evidence=f"Parameter: {param}\nOriginal ID: {orig_int} → {len(r_orig.text)} bytes\nTest ID: {test_id} → {len(r_test.text)} bytes",
                            remediation="Implement object-level authorization checks. Use indirect references (GUIDs) instead of sequential IDs. Verify ownership on every request.",
                            url=r_test.url,
                            cve="CWE-639"
                        )
                        break

        self.log(f"IDOR scan complete — {len(self.findings)} findings", "+")
        return self.result()
