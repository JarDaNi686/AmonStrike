"""
AmonStrike — False Positive Validator
Learns from mistakes. Applied to every finding before reporting.

Rules learned from vnsgu.net scan:
  SSRF: response must contain real metadata, not just homepage HTML
  RCE:  response must contain real command output pattern
  XSS:  payload must be executable, not just reflected as text
  SQLi: response must contain real DB error, not generic error page
"""
import re
import hashlib


class FalsePositiveValidator:

    def __init__(self, baseline_text: str = "", baseline_status: int = 200):
        self.baseline      = baseline_text
        self.baseline_hash = hashlib.md5(baseline_text.encode()).hexdigest()
        self.baseline_len  = len(baseline_text)
        self.rejected      = []
        self.accepted      = []

    def validate(self, finding: dict, response_text: str = "") -> bool:
        """Returns True if finding is real, False if false positive."""
        module = finding.get("module", "")
        fn     = getattr(self, f"_check_{module}", self._check_generic)
        result = fn(finding, response_text)
        if result:
            self.accepted.append(finding.get("title",""))
        else:
            self.rejected.append(finding.get("title",""))
        return result

    def validate_all(self, findings: list) -> list:
        """Filter out false positives from a list of findings."""
        return [f for f in findings if self._dispatch(f)]

    def _dispatch(self, f: dict) -> bool:
        evidence = f.get("evidence", "")
        module   = f.get("module", "")
        fn       = getattr(self, f"_check_{module}", self._check_generic)
        return fn(f, evidence)

    # ── Per-module validators ──────────────────────────────────

    def _check_ssrf(self, f: dict, evidence: str) -> bool:
        """SSRF is real: response section must contain actual metadata, not URL."""
        # Extract only the response part (after "Response:" marker)
        response_text = evidence
        for marker in ["Response:
", "Response: 
", "Response:"]:
            if marker in evidence:
                response_text = evidence[evidence.find(marker) + len(marker):]
                break

        # Homepage = false positive
        homepage = ["<!DOCTYPE html>", "<html>", "<title>", "<head>", "<meta", "favicon"]
        if sum(1 for h in homepage if h in response_text) >= 2:
            return False

        # Real metadata content (never appears in normal HTML pages)
        real = ["ami-id", "instance-id", "AccessKeyId", "SecretAccessKey",
                "local-ipv4", "serviceAccounts", "subscriptionId",
                "resourceGroupName", "instance-type", "availability-zone"]
        return any(sig in response_text for sig in real)

    
    def _check_command_injection(self, f: dict, evidence: str) -> bool:
        """RCE confirmed by real command output patterns."""
        # Real RCE: uid=33(www-data) has digits then parens
        def has_uid_output(text):
            if "uid=" not in text:
                return False
            idx = text.find("uid=")
            after = text[idx+4:idx+20]
            return any(c.isdigit() for c in after) and "(" in after

        def has_real_output(text):
            return (has_uid_output(text) or
                    "root:x:0:0:" in text or
                    "daemon:x:" in text or
                    "command not found" in text or
                    ("bytes from" in text and "icmp" in text.lower()))

        if has_real_output(evidence) and not has_real_output(self.baseline):
            return True
        return False


    def _check_sqli(self, f: dict, evidence: str) -> bool:
        """SQLi is real only if response contains actual DB error."""
        real_errors = [
            r"You have an error in your SQL syntax",
            r"mysql_fetch_array\(\)",
            r"supplied argument is not a valid MySQL",
            r"unrecognized token",
            r"sqlite3\.OperationalError",
            r"pg_query\(\).*failed",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
            r"Incorrect syntax near",
            r"Column count doesn't match",
        ]
        for pat in real_errors:
            if re.search(pat, evidence, re.I):
                if not re.search(pat, self.baseline, re.I):
                    return True
        return False

    def _check_xss(self, f: dict, evidence: str) -> bool:
        """XSS is real if payload is executable (not just reflected as text)."""
        payload = str(f.get("payload", ""))

        # Reflection-only findings need manual verification — keep as MEDIUM
        if "reflection_only" in evidence.lower() or f.get("severity") == "MEDIUM":
            # Keep it but only if it's actually in a dangerous context
            context = ""
            m = re.search(r"Context:\s*(\w+)", evidence)
            if m:
                context = m.group(1)
            return context in ["html", "attr", "js_string", "js_code"]

        # Full XSS — payload must be in response
        return payload in evidence

    def _check_rce(self, f: dict, evidence: str) -> bool:
        return self._check_command_injection(f, evidence)

    def _check_lfi(self, f: dict, evidence: str) -> bool:
        """LFI is real if actual file content is in response."""
        real_content = [
            "root:x:", "daemon:x:", "nobody:x:",  # /etc/passwd
            "[boot loader]", "for 16-bit app",      # win.ini
            "DOCUMENT_ROOT", "SERVER_SOFTWARE",      # environ
        ]
        return any(sig in evidence for sig in real_content)

    def _check_idor(self, f: dict, evidence: str) -> bool:
        """IDOR is real if different data was returned."""
        # Check evidence mentions different content
        return ("different content" in evidence.lower() or
                "secret" in evidence.lower() or
                "email" in evidence.lower() or
                "password" in evidence.lower())

    def _check_cors(self, f: dict, evidence: str) -> bool:
        """CORS is real if ACAO header reflects evil origin."""
        return ("evil.com" in evidence or
                "Access-Control-Allow-Origin: https://evil" in evidence)

    def _check_open_redirect(self, f: dict, evidence: str) -> bool:
        """Redirect is real if Location header points to evil.com."""
        return "evil.com" in evidence and "Location:" in evidence

    def _check_generic(self, f: dict, evidence: str) -> bool:
        """Default: accept if not obviously same as baseline."""
        if self._is_same_as_baseline(evidence):
            return False
        return True

    # ── Helpers ───────────────────────────────────────────────

    def _is_same_as_baseline(self, text: str) -> bool:
        """Check if response is essentially the same as homepage."""
        if not self.baseline or self.baseline_len < 100:
            return False
        # Hash match
        if hashlib.md5(text.encode()).hexdigest() == self.baseline_hash:
            return True
        # Length within 3%
        if abs(len(text) - self.baseline_len) / self.baseline_len < 0.03:
            return True
        return False

    def summary(self) -> dict:
        return {
            "accepted": len(self.accepted),
            "rejected": len(self.rejected),
            "rejected_titles": self.rejected,
        }
