"""
AmonStrike — Subdomain Takeover Detection Module
Checks for dangling DNS, unclaimed cloud resources, and takeover opportunities.
"""

import re
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule


class TakeoverModule(BaseModule):
    NAME        = "takeover"
    DESCRIPTION = "Subdomain takeover — dangling DNS, unclaimed cloud resources"

    # Vulnerable service fingerprints
    # Format: service_name: [CNAME_pattern, error_fingerprint]
    VULNERABLE_SERVICES = {
        "GitHub Pages": {
            "cname":    [".github.io"],
            "error":    ["There isn't a GitHub Pages site here"],
            "severity": "HIGH",
        },
        "Heroku": {
            "cname":    [".herokuapp.com"],
            "error":    ["no such app", "herokucdn.com/error-pages/no-such-app"],
            "severity": "HIGH",
        },
        "AWS S3": {
            "cname":    [".s3.amazonaws.com", ".s3-website"],
            "error":    ["NoSuchBucket", "The specified bucket does not exist"],
            "severity": "CRITICAL",
        },
        "Azure": {
            "cname":    [".azurewebsites.net", ".cloudapp.net"],
            "error":    ["ErrorDocument", "Microsoft Azure App Service"],
            "severity": "HIGH",
        },
        "Shopify": {
            "cname":    [".myshopify.com"],
            "error":    ["Sorry, this shop is currently unavailable"],
            "severity": "HIGH",
        },
        "Fastly": {
            "cname":    [".fastly.net"],
            "error":    ["Fastly error: unknown domain"],
            "severity": "HIGH",
        },
        "Pantheon": {
            "cname":    [".pantheonsite.io"],
            "error":    ["404 error unknown site"],
            "severity": "HIGH",
        },
        "Zendesk": {
            "cname":    [".zendesk.com"],
            "error":    ["Help Center Closed"],
            "severity": "MEDIUM",
        },
        "Tumblr": {
            "cname":    [".tumblr.com"],
            "error":    ["Whatever you were looking for doesn't currently exist"],
            "severity": "MEDIUM",
        },
        "WordPress.com": {
            "cname":    [".wordpress.com"],
            "error":    ["Do you want to register"],
            "severity": "MEDIUM",
        },
        "Ghost": {
            "cname":    [".ghost.io"],
            "error":    ["The thing you were looking for is no longer here"],
            "severity": "MEDIUM",
        },
        "Netlify": {
            "cname":    [".netlify.app", ".netlify.com"],
            "error":    ["Not Found - Request ID"],
            "severity": "HIGH",
        },
        "Vercel": {
            "cname":    [".vercel.app", ".now.sh"],
            "error":    ["The deployment you are trying to reach doesn't exist"],
            "severity": "HIGH",
        },
        "Surge.sh": {
            "cname":    [".surge.sh"],
            "error":    ["project not found"],
            "severity": "HIGH",
        },
        "Intercom": {
            "cname":    [".intercom.help"],
            "error":    ["This page is reserved for artistic works"],
            "severity": "MEDIUM",
        },
        "Acquia": {
            "cname":    [".acquia-sites.com"],
            "error":    ["If you are an Acquia Cloud customer"],
            "severity": "MEDIUM",
        },
    }

    def run(self):
        self.log("Checking for subdomain takeover opportunities...")

        domain = self.parsed.hostname

        # Gather subdomains from multiple sources
        subdomains = self._gather_subdomains(domain)
        self.info["subdomains_checked"] = len(subdomains)
        self.log(f"Checking {len(subdomains)} subdomains for takeover...", "i")

        # Check each subdomain
        vulnerable = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._check_takeover, sub): sub
                for sub in subdomains
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerable.append(result)
                    self.add_finding(
                        title=f"Subdomain Takeover: {result['subdomain']} ({result['service']})",
                        severity=result["severity"],
                        description=f"Subdomain {result['subdomain']} appears vulnerable to takeover via {result['service']}. The CNAME points to an unclaimed resource.",
                        evidence=f"Subdomain: {result['subdomain']}\nCNAME: {result['cname']}\nService: {result['service']}\nFingerprint: {result['fingerprint'][:100]}",
                        remediation=f"Remove the dangling DNS record or claim the resource on {result['service']} immediately. Unclaimed subdomains can be taken over by attackers.",
                        url=f"http://{result['subdomain']}",
                        cve="CWE-350"
                    )

        # Check for S3 bucket misconfigurations
        self._check_s3_buckets(domain)

        # Check for Azure blob storage
        self._check_azure_storage(domain)

        self.info["vulnerable_subdomains"] = vulnerable
        self.log(f"Takeover check complete — {len(vulnerable)} vulnerable subdomains", "+")
        return self.result()

    def _gather_subdomains(self, domain):
        """Gather subdomains from DNS brute force + crt.sh."""
        subdomains = set()

        # Quick DNS brute force
        common = [
            "www","mail","api","dev","staging","test","beta","app",
            "portal","dashboard","admin","secure","vpn","remote",
            "old","backup","static","cdn","assets","blog","shop",
        ]
        for prefix in common:
            subdomains.add(f"{prefix}.{domain}")

        # crt.sh
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10
            )
            if r.status_code == 200:
                for entry in r.json():
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
        except Exception:
            pass

        return list(subdomains)[:100]  # Limit for speed

    def _check_takeover(self, subdomain):
        """Check if a subdomain is vulnerable to takeover."""
        # Get CNAME record
        cname = self._get_cname(subdomain)
        if not cname:
            return None

        # Check against vulnerable services
        for service_name, config in self.VULNERABLE_SERVICES.items():
            for cname_pattern in config["cname"]:
                if cname_pattern in cname:
                    # CNAME points to potentially vulnerable service
                    # Check if the service returns takeover fingerprint
                    fingerprint = self._check_fingerprint(
                        subdomain, config["error"]
                    )
                    if fingerprint:
                        return {
                            "subdomain": subdomain,
                            "cname":     cname,
                            "service":   service_name,
                            "severity":  config["severity"],
                            "fingerprint": fingerprint,
                        }

        return None

    def _get_cname(self, subdomain):
        """Get CNAME record for subdomain."""
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", subdomain],
                capture_output=True, text=True, timeout=5
            )
            cname = result.stdout.strip().rstrip(".")
            return cname if cname else None
        except Exception:
            try:
                # Fallback: socket
                socket.gethostbyname(subdomain)
                return None  # Resolves — probably not dangling
            except socket.NXDOMAIN:
                return None
            except Exception:
                return None

    def _check_fingerprint(self, subdomain, error_patterns):
        """Check if subdomain returns takeover fingerprint."""
        for scheme in ["https", "http"]:
            try:
                r = requests.get(
                    f"{scheme}://{subdomain}",
                    timeout=5, verify=False,
                    headers={"User-Agent": "AmonStrike/2.0"}
                )
                for pattern in error_patterns:
                    if pattern.lower() in r.text.lower():
                        return pattern
            except Exception:
                pass
        return None

    def _check_s3_buckets(self, domain):
        """Check for common S3 bucket naming patterns."""
        self.log("Checking S3 bucket configurations...", "i")

        # Common S3 bucket naming patterns
        bucket_names = [
            domain,
            domain.replace(".", "-"),
            f"www.{domain}",
            f"backup.{domain}",
            f"static.{domain}",
            f"assets.{domain}",
            f"media.{domain}",
            f"uploads.{domain}",
        ]

        for bucket in bucket_names:
            # Check S3 bucket directly
            s3_urls = [
                f"https://{bucket}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{bucket}",
            ]
            for url in s3_urls:
                try:
                    r = requests.get(url, timeout=5)
                    if r.status_code == 200:
                        # Check if listing is enabled
                        if "<ListBucketResult" in r.text:
                            self.add_finding(
                                title=f"S3 Bucket Listing Enabled: {bucket}",
                                severity="CRITICAL",
                                description=f"S3 bucket '{bucket}' has public listing enabled. All files are exposed.",
                                evidence=f"URL: {url}\nResponse: {r.text[:300]}",
                                remediation="Disable S3 bucket public listing. Set bucket policy to deny s3:ListBucket for public access.",
                                url=url,
                                cve="CWE-200"
                            )
                    elif r.status_code == 403:
                        # Bucket exists but access denied — check if writable
                        self.log(f"S3 bucket exists: {bucket} (403)", "i")
                    elif "NoSuchBucket" in r.text:
                        self.log(f"S3 bucket not found: {bucket}", "~")
                except Exception:
                    pass

    def _check_azure_storage(self, domain):
        """Check for Azure blob storage misconfigurations."""
        blob_names = [
            domain.replace(".", ""),
            domain.replace(".", "-"),
        ]

        for name in blob_names[:3]:
            url = f"https://{name}.blob.core.windows.net"
            try:
                r = requests.get(url + "?comp=list", timeout=5)
                if r.status_code == 200 and "<EnumerationResults" in r.text:
                    self.add_finding(
                        title=f"Azure Blob Storage Listing Exposed: {name}",
                        severity="CRITICAL",
                        description=f"Azure blob storage container '{name}' has public listing enabled.",
                        evidence=f"URL: {url}\nResponse: {r.text[:200]}",
                        remediation="Set Azure blob storage access level to Private. Remove public access.",
                        url=url,
                        cve="CWE-200"
                    )
            except Exception:
                pass
