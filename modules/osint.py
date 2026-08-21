"""
AmonStrike — OSINT Module
Live open-source intelligence gathering.
"""
import re
import socket
import subprocess
import requests
from .base import BaseModule

class OsintModule(BaseModule):
    NAME        = "osint"
    DESCRIPTION = "OSINT — live whois, crt.sh, wayback, shodan, email harvest"

    def run(self):
        self.log("Running OSINT...")
        domain = self.parsed.hostname or ""

        self._check_whois(domain)
        self._check_crtsh(domain)
        self._check_wayback(domain)
        self._check_exposed_endpoints(domain)
        self._check_security_txt()
        self._check_email_harvest(domain)

        self.log(f"OSINT complete — {len(self.findings)} findings", "+")
        return self.result()

    def _check_whois(self, domain: str):
        try:
            out = subprocess.run(["whois", domain],
                capture_output=True, text=True, timeout=15).stdout
            # Look for sensitive info
            emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', out)
            phones = re.findall(r'Phone:\s*(.+)', out, re.I)
            if emails:
                self.add_finding(
                    title       = f"WHOIS Exposes {len(emails)} Email(s)",
                    severity    = "LOW",
                    description = f"WHOIS data contains email addresses useful for phishing and credential stuffing.",
                    evidence    = f"Emails: {', '.join(set(emails[:5]))}\nPhones: {', '.join(phones[:3])}",
                    remediation = "Enable WHOIS privacy protection with your registrar.",
                    url         = self.url,
                )
            self.info["whois_emails"] = list(set(emails))
        except Exception:
            pass

    def _check_crtsh(self, domain: str):
        try:
            r = self.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15
            )
            if r.status_code == 200:
                certs  = r.json()
                names  = set()
                for cert in certs:
                    for name in cert.get("name_value","").split("\n"):
                        name = name.strip().lstrip("*.")
                        if domain in name:
                            names.add(name)
                self.info["subdomains_crtsh"] = list(names)
                if len(names) > 20:
                    self.add_finding(
                        title       = f"Certificate Transparency Exposes {len(names)} Subdomains",
                        severity    = "INFO",
                        description = f"crt.sh reveals {len(names)} subdomains via SSL certificate logs.",
                        evidence    = f"Sample: {', '.join(list(names)[:10])}",
                        remediation = "Review each subdomain for attack surface. Consider wildcard certs.",
                        url         = f"https://crt.sh/?q=%.{domain}",
                    )
        except Exception:
            pass

    def _check_wayback(self, domain: str):
        try:
            r = self.session.get(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=200",
                timeout=20
            )
            if r.status_code == 200:
                urls = [row[0] for row in r.json()[1:] if row]
                # Find interesting endpoints
                interesting = [u for u in urls if any(
                    kw in u.lower() for kw in
                    ["admin","api","backup","config","debug","test",
                     "dev","staging","internal","dashboard","secret"]
                )]
                self.info["wayback_urls"] = urls[:100]
                if interesting:
                    self.add_finding(
                        title       = f"Wayback Machine: {len(interesting)} Sensitive Historical URLs",
                        severity    = "MEDIUM",
                        description = "Wayback Machine reveals historical sensitive endpoints that may still exist.",
                        evidence    = "\n".join(interesting[:10]),
                        remediation = "Test each URL for availability. Check if admin/debug paths are still accessible.",
                        url         = f"https://web.archive.org/web/*/{domain}",
                    )
        except Exception:
            pass

    def _check_exposed_endpoints(self, domain: str):
        """Check for common exposed sensitive files."""
        paths = [
            "/.git/config", "/.git/HEAD", "/.env", "/.env.local",
            "/wp-config.php", "/config.php", "/database.yml",
            "/composer.json", "/package.json", "/.DS_Store",
            "/phpinfo.php", "/server-status", "/server-info",
            "/.htpasswd", "/web.config", "/Dockerfile",
            "/docker-compose.yml", "/terraform.tfstate",
        ]
        for path in paths:
            r = self.get(path, allow_redirects=False)
            if not r:
                continue
            if r.status_code == 200 and len(r.text) > 10:
                sev = "CRITICAL" if any(k in path for k in [".env","config","tfstate"]) else "HIGH"
                self.add_finding(
                    title       = f"Exposed Sensitive File: {path}",
                    severity    = sev,
                    description = f"Sensitive file {path} is publicly accessible.",
                    evidence    = f"Status: {r.status_code}\nContent preview: {r.text[:200]}",
                    remediation = f"Block access to {path} via server config or .htaccess.",
                    url         = self.url + path,
                )

    def _check_security_txt(self):
        for path in ["/.well-known/security.txt", "/security.txt"]:
            r = self.get(path)
            if r and r.status_code == 200:
                self.info["security_txt"] = r.text[:500]
                self.log(f"security.txt found: {self.url+path}", "i")
                break

    def _check_email_harvest(self, domain: str):
        """Harvest emails from target website."""
        r = self.get("")
        if not r:
            return
        emails = re.findall(r'[\w.+-]+@' + re.escape(domain), r.text)
        if emails:
            self.info["harvested_emails"] = list(set(emails))
            self.add_finding(
                title       = f"Email Addresses Exposed on Website: {len(set(emails))}",
                severity    = "LOW",
                description = f"Email addresses found on the website useful for phishing and breach lookup.",
                evidence    = "\n".join(list(set(emails))[:10]),
                remediation = "Obfuscate email addresses or use contact forms.",
                url         = self.url,
            )
