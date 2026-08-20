"""
AmonStrike — Base Module
All modules inherit from this class.
"""

import requests
import urllib3
from datetime import datetime
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; D = "\033[90m"; X = "\033[0m"

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[92m",
    "INFO":     "\033[96m",
}

class BaseModule:
    """Base class for all AmonStrike modules."""

    NAME        = "base"
    DESCRIPTION = "Base module"

    def __init__(self, url, session_data):
        self.url          = url
        self.session_data = session_data
        self.parsed       = urlparse(url)
        self.timeout      = session_data.get("timeout", 10)
        self.proxy        = session_data.get("proxy")
        self.output_dir   = session_data.get("output_dir", "output")
        self.findings     = []
        self.errors       = []
        self.info         = {}

        # Set up requests session
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = self.timeout

        if self.proxy:
            self.session.proxies = self.proxy

        # Default headers
        default_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        extra = session_data.get("headers", {})
        default_headers.update(extra)
        self.session.headers.update(default_headers)

        # Cookies
        cookie_str = session_data.get("cookies", "")
        if cookie_str:
            for part in cookie_str.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

    def get(self, path="", params=None, headers=None, allow_redirects=True):
        """Make a GET request."""
        url = urljoin(self.url + "/", path.lstrip("/")) if path else self.url
        try:
            return self.session.get(
                url, params=params, headers=headers,
                allow_redirects=allow_redirects, timeout=self.timeout
            )
        except Exception as e:
            self.errors.append(str(e))
            return None

    def post(self, path="", data=None, json=None, headers=None):
        """Make a POST request."""
        url = urljoin(self.url + "/", path.lstrip("/")) if path else self.url
        try:
            return self.session.post(
                url, data=data, json=json, headers=headers, timeout=self.timeout
            )
        except Exception as e:
            self.errors.append(str(e))
            return None

    def add_finding(self, title, severity, description, evidence=None,
                    remediation=None, url=None, request=None, response=None,
                    cvss=None, cve=None):
        """Add a vulnerability finding."""
        finding = {
            "id":          f"{self.NAME}_{len(self.findings)+1:03d}",
            "module":      self.NAME,
            "title":       title,
            "severity":    severity.upper(),
            "description": description,
            "evidence":    evidence or "",
            "remediation": remediation or "",
            "url":         url or self.url,
            "request":     request or "",
            "response":    response or "",
            "cvss":        cvss or "",
            "cve":         cve or "",
            "timestamp":   datetime.now().isoformat(),
        }
        self.findings.append(finding)
        color = SEVERITY_COLORS.get(severity.upper(), D)
        print(f"    {color}[{severity.upper()}]{X} {title}")
        return finding

    def log(self, msg, level="*"):
        colors = {"*": D, "!": R, "+": G, "~": Y, "i": C}
        c = colors.get(level, D)
        print(f"    {c}[{level}]{X} {msg}")

    def run(self):
        """Override in subclass. Return dict with findings and info."""
        raise NotImplementedError

    def result(self):
        """Return standardized result dict."""
        return {
            "module":   self.NAME,
            "desc":     self.DESCRIPTION,
            "findings": self.findings,
            "info":     self.info,
            "errors":   self.errors,
        }
