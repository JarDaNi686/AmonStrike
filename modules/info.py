"""AmonStrike — Information Disclosure Module"""
import re
from .base import BaseModule

class InfoModule(BaseModule):
    NAME = "info"
    DESCRIPTION = "Information disclosure — errors, comments, metadata, emails"

    def run(self):
        self.log("Checking for information disclosure...")
        resp = self.get()
        if not resp:
            return self.result()

        self._check_html_comments(resp)
        self._check_error_pages()
        self._check_emails(resp)
        self._check_internal_ips(resp)
        self._check_debug_info(resp)
        self._check_version_strings(resp)
        self._check_meta_tags(resp)

        self.log(f"Info disclosure scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _check_html_comments(self, resp):
        comments = re.findall(r'<!--(.*?)-->', resp.text, re.DOTALL)
        sensitive_comments = []
        for c in comments:
            c_clean = c.strip()
            if len(c_clean) > 5 and any(s in c_clean.lower() for s in
               ["todo", "fixme", "hack", "password", "key", "secret", "api", "admin", "debug", "test", "config"]):
                sensitive_comments.append(c_clean[:200])

        if sensitive_comments:
            self.add_finding(
                title="Sensitive Information in HTML Comments",
                severity="MEDIUM",
                description=f"HTML comments contain potentially sensitive information ({len(sensitive_comments)} found).",
                evidence="Sensitive comments:\n" + "\n---\n".join(sensitive_comments[:3]),
                remediation="Remove all HTML comments from production code. Use version control for tracking changes.",
                url=self.url,
                cve="CWE-615"
            )

    def _check_error_pages(self):
        """Trigger error pages and check for information disclosure."""
        test_paths = [
            "/nonexistent-page-amonstrike",
            "/../../etc/passwd",
            "/' OR '1'='1",
            "/<script>alert(1)</script>",
        ]
        for path in test_paths:
            r = self.get(path)
            if r and r.status_code in [400, 404, 500, 503]:
                # Check for stack traces or server info in errors
                indicators = [
                    ("stack trace", "Stack Trace Disclosure"),
                    ("exception", "Exception Details Disclosed"),
                    ("traceback", "Python Traceback Disclosed"),
                    ("at com.", "Java Stack Trace Disclosed"),
                    ("Fatal error:", "PHP Fatal Error Disclosed"),
                    ("Warning:", "PHP Warning Disclosed"),
                    ("mysql_fetch", "MySQL Error Disclosed"),
                    ("ORA-", "Oracle Error Disclosed"),
                ]
                for ind, title in indicators:
                    if ind.lower() in r.text.lower():
                        self.add_finding(
                            title=f"Error Page Discloses {title}",
                            severity="MEDIUM",
                            description=f"Error page reveals internal information: {title}. This helps attackers understand the system architecture.",
                            evidence=f"GET {path} → {r.status_code}\nContains: {ind}\nSnippet: {r.text[:300]}",
                            remediation="Configure custom error pages. Disable detailed error messages in production. Log errors server-side only.",
                            url=self.url + path,
                            cve="CWE-209"
                        )
                        break

    def _check_emails(self, resp):
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
        emails = list(set(emails))
        if emails:
            self.info["emails_found"] = emails[:10]
            self.add_finding(
                title=f"Email Addresses Exposed ({len(emails)} found)",
                severity="LOW",
                description="Email addresses found in page source. Can be used for phishing or account enumeration.",
                evidence="Emails: " + ", ".join(emails[:5]),
                remediation="Obfuscate email addresses in HTML. Use contact forms instead of direct email links.",
                url=self.url,
                cve="CWE-359"
            )

    def _check_internal_ips(self, resp):
        ip_pattern = r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'
        ips = re.findall(ip_pattern, resp.text)
        if ips:
            unique_ips = list(set(ips))
            self.info["internal_ips"] = unique_ips
            self.add_finding(
                title=f"Internal IP Addresses Disclosed ({len(unique_ips)} found)",
                severity="MEDIUM",
                description="Internal/private IP addresses found in page source. Reveals network architecture.",
                evidence="IPs: " + ", ".join(unique_ips[:5]),
                remediation="Remove internal IP references from public-facing code. Use domain names instead.",
                url=self.url,
                cve="CWE-497"
            )

    def _check_debug_info(self, resp):
        debug_patterns = [
            (r'DEBUG\s*=\s*True', "Django DEBUG Mode"),
            (r'APP_DEBUG.*true', "Laravel Debug Mode"),
            (r'display_errors\s*=\s*On', "PHP display_errors On"),
            (r'WP_DEBUG.*true', "WordPress Debug Mode"),
            (r'console\.log\(.*password', "Password in console.log"),
            (r'console\.log\(.*token', "Token in console.log"),
        ]
        for pattern, title in debug_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                self.add_finding(
                    title=f"Debug Mode Enabled: {title}",
                    severity="HIGH",
                    description=f"{title} detected. Debug mode exposes sensitive error details and configuration.",
                    evidence=f"Pattern found: {pattern}",
                    remediation=f"Disable debug mode in production. Set DEBUG=False, display_errors=Off, etc.",
                    url=self.url,
                    cve="CWE-94"
                )

    def _check_version_strings(self, resp):
        version_patterns = [
            r'jQuery v(\d+\.\d+\.\d+)',
            r'Bootstrap v(\d+\.\d+\.\d+)',
            r'Angular\s+(\d+\.\d+\.\d+)',
            r'React\s+v(\d+\.\d+\.\d+)',
            r'Vue\.js\s+v(\d+\.\d+\.\d+)',
        ]
        found_versions = []
        for pattern in version_patterns:
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            if matches:
                found_versions.extend(matches)

        if found_versions:
            self.info["js_versions"] = found_versions
            self.add_finding(
                title=f"JavaScript Library Versions Exposed",
                severity="LOW",
                description=f"JavaScript library versions found: {', '.join(found_versions)}. Outdated versions may have known CVEs.",
                evidence="Versions: " + ", ".join(found_versions),
                remediation="Keep libraries updated. Remove version information from source code.",
                url=self.url
            )

    def _check_meta_tags(self, resp):
        generator = re.search(r'<meta name="generator" content="([^"]+)"', resp.text, re.I)
        if generator:
            self.info["generator"] = generator.group(1)
            self.add_finding(
                title=f"Generator Meta Tag: {generator.group(1)}",
                severity="INFO",
                description="Generator meta tag reveals CMS or framework version.",
                evidence=f'<meta name="generator" content="{generator.group(1)}">',
                remediation="Remove generator meta tag from HTML.",
                url=self.url
            )
