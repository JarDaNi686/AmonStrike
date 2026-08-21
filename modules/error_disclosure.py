"""AmonStrike - Error Disclosure Module"""
import re
from .base import BaseModule

ERROR_TRIGGERS = ["'", '"', "--", ";", "{{", "}}", "1/0", "null", "undefined"]

STACK_PATTERNS = [
    "Traceback (most recent call last)",
    "Exception in thread",
    "Fatal error:",
    "Warning:",
    "Parse error:",
    "Unhandled exception",
    "ORA-",
    "PostgreSQL",
    "mysql_fetch",
    "You have an error in your SQL syntax",
    "/var/www/",
    "/home/",
    "C:\\inetpub",
    "System.NullReferenceException",
    "Microsoft.CSharp",
]

class ErrorDisclosureModule(BaseModule):
    NAME        = "error_disclosure"
    DESCRIPTION = "Error disclosure - stack traces, DB errors, internal paths"

    def run(self):
        self.log("Testing error disclosure...")
        self._test_error_triggers()
        self._test_missing_routes()
        self.log(f"Error disclosure complete - {len(self.findings)} findings", "+")
        return self.result()

    def _test_error_triggers(self):
        for payload in ERROR_TRIGGERS:
            for param in ["id", "q", "search", "page", "item", "user", "data"]:
                r = self.get(params={param: payload})
                if r and self._has_stack(r.text):
                    self._report(param, payload, r)
                    return

    def _test_missing_routes(self):
        for path in ["/api/nonexistent_12345", "/undefined/route"]:
            r = self.get(path)
            if r and self._has_stack(r.text):
                self._report("path", path, r)
                break

    def _has_stack(self, text):
        return any(p in text for p in STACK_PATTERNS)

    def _report(self, param, payload, r):
        patterns_found = [p for p in STACK_PATTERNS if p in r.text]
        paths_found = re.findall(r"(/[\w/.-]+\.(?:py|php|js|java|cs|rb))", r.text)
        self.add_finding(
            title       = "Verbose Error Disclosure - Stack Trace/Internal Paths Exposed",
            severity    = "MEDIUM",
            description = (
                "Application returns detailed error messages including stack traces "
                "and internal file paths, exposing server technology and attack surface."
            ),
            evidence    = (
                f"Trigger: {param}={payload}\n"
                f"Patterns found: {patterns_found[:3]}\n"
                f"Paths exposed: {paths_found[:5]}\n"
                f"Error snippet: {r.text[:500]}"
            ),
            remediation = (
                "Set DEBUG=False in production. "
                "Return generic error messages to users. "
                "Log detailed errors server-side only."
            ),
            url=self.url, parameter=param, payload=payload, cve="CWE-209",
        )
