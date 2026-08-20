"""
AmonStrike — HackerOne Submission Format Generator
Produces professional, submission-ready reports for HackerOne.

A rejected report costs you time and reputation.
A well-written report wins bounties and builds relationships.

This generator produces the exact format H1 triagers prefer:
  - Clear summary
  - Numbered reproduction steps
  - Full HTTP evidence
  - Impact statement
  - CVSS vector
  - Suggested severity
"""

import os
import json
from datetime import datetime


class HackerOneFormat:
    """
    Generates HackerOne-ready vulnerability reports.
    Follows H1 best practices for triage acceptance.
    """

    # H1 severity mapping
    H1_SEVERITY = {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
        "INFO":     "informational",
    }

    # H1 weakness categories (CWE mapping)
    H1_WEAKNESS = {
        "sqli":          {"id": 89,  "name": "SQL Injection"},
        "xss":           {"id": 79,  "name": "Cross-site Scripting (XSS) - Reflected"},
        "ssrf":          {"id": 918, "name": "Server-Side Request Forgery (SSRF)"},
        "idor":          {"id": 639, "name": "Authorization Bypass Through User-Controlled Key"},
        "lfi":           {"id": 22,  "name": "Path Traversal"},
        "rce":           {"id": 77,  "name": "Command Injection"},
        "xxe":           {"id": 611, "name": "XML External Entities (XXE)"},
        "csrf":          {"id": 352, "name": "Cross-Site Request Forgery (CSRF)"},
        "cors":          {"id": 942, "name": "Permissive Cross-domain Policy"},
        "auth":          {"id": 287, "name": "Improper Authentication"},
        "ssti":          {"id": 94,  "name": "Improper Control of Generation of Code"},
        "jwt":           {"id": 347, "name": "Improper Verification of Cryptographic Signature"},
        "takeover":      {"id": 116, "name": "Improper Encoding or Escaping of Output"},
        "credentials":   {"id": 798, "name": "Use of Hard-coded Credentials"},
        "http_smuggling":{"id": 444, "name": "Inconsistent Interpretation of HTTP Requests"},
    }

    def generate(self, finding: dict, program: dict = None) -> dict:
        """
        Generate a complete HackerOne submission.
        Returns dict with all fields ready for API or manual submission.
        """
        module   = finding.get("module","")
        sev      = finding.get("severity","MEDIUM")
        weakness = self.H1_WEAKNESS.get(module, {"id": 0, "name": "Other"})

        # Get CVSS if available
        cvss_score  = finding.get("cvss_score", 0)
        cvss_vector = finding.get("cvss_vector", "")

        submission = {
            # H1 API fields
            "title":             self._generate_title(finding),
            "vulnerability_information": self._generate_body(finding),
            "impact":            self._generate_impact(finding),
            "severity":          self.H1_SEVERITY.get(sev, "medium"),
            "cvss_vector":       cvss_vector or self._default_cvss(module, sev),
            "weakness_id":       weakness["id"],
            "weakness_name":     weakness["name"],

            # Metadata
            "program":           program.get("handle","") if program else "",
            "submitted_at":      datetime.now().isoformat(),
            "tool":              "AmonStrike v2.0",
        }

        return submission

    def _generate_title(self, finding: dict) -> str:
        """Generate a clear, descriptive title."""
        title  = finding.get("title","")
        url    = finding.get("url","")
        module = finding.get("module","")

        # Clean up auto-generated titles
        if title and len(title) > 10:
            return title[:100]

        # Generate from module
        templates = {
            "sqli":   f"SQL Injection at {self._extract_path(url)}",
            "xss":    f"Reflected XSS at {self._extract_path(url)}",
            "ssrf":   f"SSRF via {finding.get('parameter','URL parameter')} at {self._extract_path(url)}",
            "idor":   f"IDOR — Unauthorized Access to Other Users' Data at {self._extract_path(url)}",
            "lfi":    f"Path Traversal / LFI at {self._extract_path(url)}",
            "rce":    f"Remote Code Execution at {self._extract_path(url)}",
            "xxe":    f"XXE Injection at {self._extract_path(url)}",
            "takeover": f"Subdomain Takeover: {finding.get('url','')}",
        }
        return templates.get(module, title or f"Security Issue at {url}")[:100]

    def _generate_body(self, finding: dict) -> str:
        """Generate the full vulnerability description in H1 markdown format."""
        title   = finding.get("title","")
        desc    = finding.get("description","")
        evidence= finding.get("evidence","")
        poc     = finding.get("poc_steps", [])
        url     = finding.get("url","")
        param   = finding.get("parameter","")
        payload = finding.get("payload","")

        body = f"## Summary\n\n{desc}\n\n"

        body += "## Steps to Reproduce\n\n"
        if poc and isinstance(poc, list):
            for step in poc:
                body += f"{step}\n"
        else:
            body += f"1. Navigate to: `{url}`\n"
            if param and payload:
                body += f"2. Set parameter `{param}` to: `{payload}`\n"
            body += f"3. Observe: {desc[:200]}\n"

        body += "\n## Evidence\n\n"
        if evidence:
            body += f"```\n{evidence[:2000]}\n```\n\n"

        body += "## Impact\n\n"
        body += self._generate_impact(finding) + "\n\n"

        body += f"---\n*Discovered by AmonStrike v2.0 | {datetime.now().strftime('%Y-%m-%d')}*"

        return body

    def _generate_impact(self, finding: dict) -> str:
        """Generate detailed impact statement."""
        sev    = finding.get("severity","MEDIUM")
        module = finding.get("module","")
        desc   = finding.get("description","")

        impact_templates = {
            "sqli":   ("An attacker can extract all data from the database, "
                       "bypass authentication, and potentially execute OS commands "
                       "via SQL injection. This exposes all user records, "
                       "passwords (even hashed), and potentially allows full "
                       "server compromise."),
            "xss":    ("An attacker can execute arbitrary JavaScript in victims' "
                       "browsers. This enables session token theft, account "
                       "takeover, keylogging, phishing within the trusted domain, "
                       "and spreading to other users automatically."),
            "ssrf":   ("An attacker can make the server issue requests to internal "
                       "services, cloud metadata APIs (AWS/GCP/Azure), and "
                       "potentially pivot to the internal network. This often "
                       "leads to credential theft and full cloud account compromise."),
            "idor":   ("An attacker can access, modify, or delete any other user's "
                       "data by simply changing an ID parameter. This constitutes "
                       "a complete authorization bypass affecting all users."),
            "rce":    ("An attacker can execute arbitrary operating system commands "
                       "on the server, achieving complete system compromise, "
                       "data exfiltration, and lateral movement within the network."),
            "lfi":    ("An attacker can read sensitive files from the server "
                       "filesystem including configuration files, credentials, "
                       "private keys, and source code."),
            "takeover":("An attacker can take control of this subdomain and serve "
                       "malicious content under the organization's trusted domain, "
                       "enabling phishing, cookie theft, and reputational damage."),
            "xxe":    ("An attacker can read arbitrary files from the server "
                       "filesystem and potentially achieve SSRF to reach internal "
                       "services."),
        }

        template = impact_templates.get(module, desc[:500] if desc else
                   f"This {sev.lower()} severity issue impacts the confidentiality, "
                   f"integrity, or availability of the application.")

        return template

    def _default_cvss(self, module: str, severity: str) -> str:
        """Return default CVSS vector when not calculated."""
        defaults = {
            "sqli":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "xss":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "ssrf":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
            "idor":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "rce":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "lfi":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "CRITICAL":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "HIGH":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "MEDIUM": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "LOW":    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        }
        return defaults.get(module, defaults.get(severity, ""))

    def _extract_path(self, url: str) -> str:
        """Extract path from URL for titles."""
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            return p.path or url[:50]
        except Exception:
            return url[:50]

    def save(self, submission: dict, output_dir: str) -> str:
        """Save submission to file."""
        os.makedirs(output_dir, exist_ok=True)
        safe_title = submission["title"][:40].replace("/","_").replace(" ","_")
        path = os.path.join(output_dir, f"h1_{safe_title}.md")
        with open(path, "w") as f:
            f.write(f"# {submission['title']}\n\n")
            f.write(f"**Severity:** {submission['severity'].upper()}\n")
            f.write(f"**CVSS:** {submission.get('cvss_vector','')}\n")
            f.write(f"**Weakness:** CWE-{submission.get('weakness_id','')} — {submission.get('weakness_name','')}\n\n")
            f.write("---\n\n")
            f.write(submission.get("vulnerability_information",""))
        return path


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    import tempfile
    print("\n=== HACKERONE FORMAT REGRESSION TESTS ===")
    passed = failed = 0
    gen = HackerOneFormat()
    tmp = tempfile.mkdtemp()

    sample = {
        "title":       "SQL Injection in login form",
        "severity":    "CRITICAL",
        "module":      "sqli",
        "url":         "http://testco.com/login?id=1",
        "parameter":   "id",
        "payload":     "' OR 1=1--",
        "description": "SQL injection allows authentication bypass",
        "evidence":    "mysql error: You have an error in your SQL syntax",
        "remediation": "Use parameterized queries",
    }

    tests = [
        ("Generate submission",
         lambda: isinstance(gen.generate(sample), dict)),

        ("Submission has title",
         lambda: len(gen.generate(sample)["title"]) > 5),

        ("Severity mapped correctly",
         lambda: gen.generate(sample)["severity"] == "critical"),

        ("Weakness ID set for sqli",
         lambda: gen.generate(sample)["weakness_id"] == 89),

        ("Body contains Summary",
         lambda: "## Summary" in gen.generate(sample)["vulnerability_information"]),

        ("Body contains Steps to Reproduce",
         lambda: "Steps to Reproduce" in gen.generate(sample)["vulnerability_information"]),

        ("Body contains Impact",
         lambda: "Impact" in gen.generate(sample)["vulnerability_information"]),

        ("Impact statement for sqli is specific",
         lambda: "database" in gen._generate_impact(sample).lower()),

        ("Impact statement for xss is specific",
         lambda: "javascript" in gen._generate_impact({**sample,"module":"xss"}).lower()),

        ("CVSS default for sqli",
         lambda: "AV:N" in gen._default_cvss("sqli","CRITICAL")),

        ("Path extracted from URL",
         lambda: "/login" in gen._extract_path("http://testco.com/login?id=1")),

        ("Save generates markdown file",
         lambda: (
             sub := gen.generate(sample),
             path := gen.save(sub, tmp),
             os.path.exists(path)
         )[2]),

        ("Saved file contains severity",
         lambda: (
             sub := gen.generate(sample),
             path := gen.save(sub, tmp),
             "CRITICAL" in open(path).read()
         )[2]),
    ]

    for name, fn in tests:
        try:
            if fn():
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    rp, rf = run_regression_tests()
    sys.exit(0 if rf == 0 else 1)
