"""
AmonStrike — OSINT Layer
Passive reconnaissance before touching the target.

Sources:
  - theHarvester (emails, subdomains, hosts)
  - amass / subfinder (subdomain enumeration)
  - crt.sh (certificate transparency)
  - Wayback Machine (historical endpoints)
  - GitHub dorking (leaked secrets, configs)
  - DNS brute force
  - WHOIS / ASN lookup
  - Shodan (if API key provided)
  - Google dorking (automated)
"""

import re
import json
import time
import socket
import threading
import requests
import subprocess
import shutil
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule


class OsintModule(BaseModule):
    NAME        = "osint"
    DESCRIPTION = "OSINT — subdomains, emails, historical endpoints, leaked secrets"

    # Google dork templates
    GOOGLE_DORKS = [
        'site:{domain} filetype:env',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:log',
        'site:{domain} "password" OR "passwd" OR "secret"',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:backup',
        'site:{domain} inurl:config',
        'site:{domain} intitle:"index of"',
        '"@{domain}" email',
        'site:github.com "{domain}" password OR secret OR key',
        'site:pastebin.com "{domain}"',
    ]

    # Common subdomain prefixes for brute force
    SUBDOMAIN_WORDLIST = [
        "www","mail","ftp","smtp","pop","ns","webmail","server",
        "ns1","ns2","ns3","admin","secure","vpn","remote","api",
        "dev","staging","test","beta","app","portal","dashboard",
        "m","mobile","cdn","static","assets","img","images","media",
        "blog","forum","shop","store","pay","payment","checkout",
        "login","auth","sso","accounts","id","oauth","oidc",
        "api2","api3","v1","v2","internal","intranet","extranet",
        "git","gitlab","jenkins","ci","jira","confluence","wiki",
        "backup","old","legacy","archive","new","prod","production",
        "qa","uat","preview","demo","sandbox","cloud","status",
        "monitor","metrics","grafana","kibana","elastic","splunk",
        "smtp","mx","mail2","webmail2","exchange","outlook",
    ]

    def run(self):
        self.log("Starting OSINT reconnaissance...")

        domain = self.parsed.hostname
        self.info["domain"] = domain
        self.info["subdomains"]    = set()
        self.info["emails"]        = set()
        self.info["endpoints"]     = set()
        self.info["leaked_secrets"]= []
        self.info["asn"]           = {}
        self.info["whois"]         = {}

        # Run all OSINT sources
        self._run_theharvester(domain)
        self._run_subfinder(domain)
        self._run_amass(domain)
        self._run_crt_sh(domain)
        self._run_wayback(domain)
        self._run_dns_brute(domain)
        self._run_github_dork(domain)
        self._run_whois(domain)
        self._run_asn_lookup(domain)
        self._check_shodan(domain)

        # Convert sets to lists for JSON serialization
        self.info["subdomains"] = list(self.info["subdomains"])
        self.info["emails"]     = list(self.info["emails"])
        self.info["endpoints"]  = list(self.info["endpoints"])

        # Report findings
        n_subs   = len(self.info["subdomains"])
        n_emails = len(self.info["emails"])
        n_eps    = len(self.info["endpoints"])

        if n_subs:
            self.add_finding(
                title=f"Subdomains Discovered ({n_subs})",
                severity="INFO",
                description=f"OSINT discovered {n_subs} subdomains for {domain}.",
                evidence="Subdomains:\n" + "\n".join(self.info["subdomains"][:20]),
                remediation="Review each subdomain for unnecessary exposure. Remove unused subdomains.",
                url=self.url
            )

        if n_emails:
            self.add_finding(
                title=f"Email Addresses Discovered ({n_emails})",
                severity="LOW",
                description=f"OSINT discovered {n_emails} email addresses associated with {domain}.",
                evidence="Emails:\n" + "\n".join(list(self.info["emails"])[:10]),
                remediation="Be aware of social engineering risk. Consider email harvesting protection.",
                url=self.url
            )

        if n_eps:
            self.add_finding(
                title=f"Historical Endpoints Found ({n_eps})",
                severity="MEDIUM",
                description=f"Wayback Machine reveals {n_eps} historical endpoints. Some may still be active.",
                evidence="Endpoints:\n" + "\n".join(list(self.info["endpoints"])[:20]),
                remediation="Test historical endpoints for active access. Remove or protect deprecated endpoints.",
                url=self.url
            )

        self.log(f"OSINT complete — {n_subs} subdomains, {n_emails} emails, {n_eps} endpoints", "+")
        return self.result()

    def _run_theharvester(self, domain):
        """Run theHarvester for email + subdomain collection."""
        if not shutil.which("theHarvester"):
            self.log("theHarvester not available — using built-in", "~")
            return

        self.log("Running theHarvester...", "i")
        try:
            result = subprocess.run(
                ["theHarvester", "-d", domain, "-b", "google,bing,yahoo,dnsdumpster",
                 "-l", "50", "-f", "/tmp/theharvester_out"],
                capture_output=True, text=True, timeout=60
            )
            output = result.stdout + result.stderr

            # Parse emails
            emails = re.findall(r'[\w.+-]+@' + re.escape(domain), output, re.I)
            self.info["emails"].update(emails)

            # Parse subdomains
            subs = re.findall(r'[\w.-]+\.' + re.escape(domain), output, re.I)
            self.info["subdomains"].update(s.lower() for s in subs if s != domain)

            self.log(f"theHarvester: {len(emails)} emails, {len(subs)} subdomains", "+")

        except subprocess.TimeoutExpired:
            self.log("theHarvester timed out", "~")
        except Exception as e:
            self.log(f"theHarvester error: {e}", "~")

    def _run_subfinder(self, domain):
        """Run subfinder for passive subdomain enumeration."""
        if not shutil.which("subfinder"):
            self.log("subfinder not available", "~")
            return

        self.log("Running subfinder...", "i")
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-t", "50"],
                capture_output=True, text=True, timeout=60
            )
            subs = [s.strip() for s in result.stdout.strip().split("\n")
                   if s.strip() and "." in s]
            self.info["subdomains"].update(subs)
            self.log(f"subfinder: {len(subs)} subdomains", "+")
        except Exception as e:
            self.log(f"subfinder error: {e}", "~")

    def _run_amass(self, domain):
        """Run amass for passive subdomain enumeration."""
        if not shutil.which("amass"):
            self.log("amass not available", "~")
            return

        self.log("Running amass (passive)...", "i")
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", domain, "-timeout", "2"],
                capture_output=True, text=True, timeout=120
            )
            subs = [s.strip() for s in result.stdout.strip().split("\n")
                   if s.strip() and domain in s]
            self.info["subdomains"].update(subs)
            self.log(f"amass: {len(subs)} subdomains", "+")
        except Exception as e:
            self.log(f"amass error: {e}", "~")

    def _run_crt_sh(self, domain):
        """Query crt.sh certificate transparency logs."""
        self.log("Querying crt.sh...", "i")
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15, headers={"User-Agent": "AmonStrike/2.0"}
            )
            if r.status_code == 200:
                data = r.json()
                subs = set()
                for entry in data:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            subs.add(name.lower())

                self.info["subdomains"].update(subs)
                self.log(f"crt.sh: {len(subs)} subdomains from cert transparency", "+")

                if len(subs) > 20:
                    self.add_finding(
                        title=f"Large Attack Surface via Certificate Transparency ({len(subs)} subdomains)",
                        severity="INFO",
                        description="Certificate transparency logs reveal a large number of subdomains. Each is a potential attack surface.",
                        evidence=f"crt.sh found {len(subs)} unique subdomains",
                        remediation="Audit all subdomains. Remove unused ones. Use private CAs for internal services.",
                        url=f"https://crt.sh/?q=%.{domain}"
                    )
        except Exception as e:
            self.log(f"crt.sh error: {e}", "~")

    def _run_wayback(self, domain):
        """Query Wayback Machine for historical endpoints."""
        self.log("Querying Wayback Machine...", "i")
        try:
            api = (f"http://web.archive.org/cdx/search/cdx"
                   f"?url={domain}/*&output=json&limit=100"
                   f"&filter=statuscode:200&fl=original&collapse=urlkey")
            r = requests.get(api, timeout=15)
            if r.status_code == 200:
                data = r.json()
                endpoints = set()
                for entry in data[1:]:  # Skip header
                    url = entry[0]
                    # Filter interesting endpoints
                    if any(ext in url for ext in
                           [".php", ".asp", ".jsp", "?", "/api/", "/admin",
                            "/login", "/config", "/backup"]):
                        endpoints.add(url)

                self.info["endpoints"].update(endpoints)

                # Check for interesting historical paths
                sensitive = [e for e in endpoints if any(s in e.lower() for s in
                    ["admin", "config", "backup", "secret", "password", "api/key"])]
                if sensitive:
                    self.add_finding(
                        title=f"Sensitive Historical Endpoints in Wayback ({len(sensitive)})",
                        severity="MEDIUM",
                        description="Wayback Machine reveals historical sensitive endpoints that may still be accessible.",
                        evidence="Sensitive paths:\n" + "\n".join(sensitive[:10]),
                        remediation="Test if these endpoints are still accessible. Implement proper access controls.",
                        url=f"https://web.archive.org/web/*/{domain}"
                    )

                self.log(f"Wayback: {len(endpoints)} historical endpoints", "+")
        except Exception as e:
            self.log(f"Wayback error: {e}", "~")

    def _run_dns_brute(self, domain):
        """DNS brute force with common prefixes."""
        self.log("Running DNS brute force...", "i")
        found = []

        def resolve(sub):
            try:
                fqdn = f"{sub}.{domain}"
                socket.gethostbyname(fqdn)
                return fqdn
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(resolve, sub): sub
                      for sub in self.SUBDOMAIN_WORDLIST}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        self.info["subdomains"].update(found)
        if found:
            self.log(f"DNS brute: {len(found)} subdomains resolved", "+")

    def _run_github_dork(self, domain):
        """Search GitHub for leaked secrets related to domain."""
        self.log("Checking GitHub for leaked data...", "i")

        # Use GitHub search API (unauthenticated — rate limited)
        dork_queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
        ]

        for query in dork_queries[:2]:  # Limit to avoid rate limiting
            try:
                r = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 5},
                    headers={"Accept": "application/vnd.github.v3+json"},
                    timeout=10
                )
                if r.status_code == 200:
                    data = r.json()
                    items = data.get("items", [])
                    if items:
                        self.info["leaked_secrets"].extend([
                            {"repo": i.get("repository", {}).get("full_name", ""),
                             "file": i.get("name", ""),
                             "url":  i.get("html_url", "")}
                            for i in items
                        ])
                        self.add_finding(
                            title=f"Potential Secrets Found on GitHub ({len(items)} results)",
                            severity="HIGH",
                            description=f"GitHub search for '{query}' returned results. Manual review required.",
                            evidence="\n".join([
                                f"{i.get('repository',{}).get('full_name','')} — {i.get('name','')}"
                                for i in items[:5]
                            ]),
                            remediation="Review GitHub results immediately. Rotate any exposed credentials. Use secret scanning in CI/CD.",
                            url=f"https://github.com/search?q={query}&type=code"
                        )
                time.sleep(2)  # Rate limit
            except Exception as e:
                self.log(f"GitHub dork error: {e}", "~")
                break

    def _run_whois(self, domain):
        """Get WHOIS information."""
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout

            # Extract registrant info
            registrant = re.search(r"Registrant.*?:\s*(.+)", output, re.I)
            if registrant:
                self.info["whois"]["registrant"] = registrant.group(1).strip()

            # Extract emails from WHOIS
            whois_emails = re.findall(r'[\w.+-]+@[\w.-]+\.\w+', output)
            self.info["emails"].update(whois_emails)

            # Check if privacy protected
            if "privacy" in output.lower() or "protected" in output.lower():
                self.info["whois"]["privacy"] = True
            else:
                self.info["whois"]["privacy"] = False
                if whois_emails:
                    self.add_finding(
                        title="WHOIS Data Exposes Contact Information",
                        severity="LOW",
                        description="WHOIS record contains unredacted contact information including emails.",
                        evidence=f"Emails found in WHOIS: {', '.join(whois_emails[:3])}",
                        remediation="Enable WHOIS privacy protection through your registrar.",
                        url=f"https://whois.domaintools.com/{domain}"
                    )
        except Exception as e:
            self.log(f"WHOIS error: {e}", "~")

    def _run_asn_lookup(self, domain):
        """Get ASN and IP range information."""
        try:
            ip = socket.gethostbyname(domain)
            r = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=10, headers={"User-Agent": "AmonStrike/2.0"}
            )
            if r.status_code == 200:
                data = r.json()
                self.info["asn"] = {
                    "ip":      ip,
                    "org":     data.get("org", ""),
                    "country": data.get("country", ""),
                    "region":  data.get("region", ""),
                    "city":    data.get("city", ""),
                }
                self.log(f"ASN: {data.get('org','')} — {data.get('country','')}", "i")
        except Exception as e:
            self.log(f"ASN lookup error: {e}", "~")

    def _check_shodan(self, domain):
        """Check Shodan if API key is configured."""
        shodan_key = os.environ.get("SHODAN_API_KEY", "")
        if not shodan_key:
            self.log("No SHODAN_API_KEY — skipping Shodan", "~")
            return

        try:
            ip = socket.gethostbyname(domain)
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}",
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])

                self.info["shodan"] = {"ports": ports, "vulns": list(vulns)}

                if vulns:
                    self.add_finding(
                        title=f"Shodan CVEs Found ({len(vulns)})",
                        severity="HIGH",
                        description=f"Shodan reports {len(vulns)} CVEs for this host.",
                        evidence=f"CVEs: {', '.join(list(vulns)[:5])}",
                        remediation="Apply security patches for listed CVEs immediately.",
                        url=f"https://www.shodan.io/host/{ip}"
                    )
        except Exception as e:
            self.log(f"Shodan error: {e}", "~")


import os
