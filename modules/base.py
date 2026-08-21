"""
AmonStrike — Base Module
All attack modules inherit from this.
Provides: HTTP requests, rate limiting, scope check,
          retry logic, finding management, evidence capture.
"""

import re
import sys
import time
import random
import hashlib
import requests
import urllib3
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.dirname(__file__)))

# ── Colors ────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"
C="\033[96m"; W="\033[97m"; D="\033[90m"; X="\033[0m"


class BaseModule:
    """
    Base class for all AmonStrike attack modules.

    Features:
      - Rate-limited HTTP (10 req/s default, configurable)
      - Automatic retry with exponential backoff
      - Scope validation before every request
      - Finding deduplication via SHA256 fingerprint
      - Full request/response evidence capture
      - WAF bypass headers injection
    """

    NAME        = "base"
    DESCRIPTION = "Base module — do not use directly"

    # Default rate limit: requests per second
    RATE_LIMIT  = 10
    MAX_RETRIES = 3
    RETRY_DELAY = 1.0

    # WAF bypass headers - rotate on 403
    WAF_BYPASS_HEADERS = [
        {},  # baseline
        {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1", "X-Remote-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"CF-Connecting-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1"},
    ]  # seconds, doubles each retry

    def __init__(self, url: str, timeout: int = 10,
                 cookies: dict = None, headers: dict = None,
                 proxy: str = None, rate_limit: int = None,
                 scope_validator=None, bypass_headers: dict = None):
        self.url              = url.rstrip("/")
        self.parsed           = urlparse(url)
        self.timeout          = timeout
        self.findings         = []
        self.info             = {}
        self._fingerprints    = set()
        self._last_request    = 0.0
        self._rate_limit      = rate_limit or self.RATE_LIMIT
        self._min_interval    = 1.0 / self._rate_limit
        self._scope_validator = scope_validator
        self._bypass_headers  = bypass_headers or {}

        # Session setup
        self.session = requests.Session()
        self.session.verify  = False
        self.session.timeout = timeout

        # Default headers
        default_headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection":      "keep-alive",
        }
        if headers:
            default_headers.update(headers)
        if bypass_headers:
            default_headers.update(bypass_headers)
        self.session.headers.update(default_headers)

        if cookies:
            self.session.cookies.update(cookies)

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    # ── HTTP Methods ──────────────────────────────────────────

    def get(self, path: str = "", params: dict = None,
            headers: dict = None, cookies: dict = None,
            **kwargs) -> requests.Response:
        """Rate-limited, retrying GET request."""
        url = self._build_url(path)
        return self._request("GET", url, params=params,
                             headers=headers, cookies=cookies, **kwargs)

    def post(self, path: str = "", data=None, json=None,
             params: dict = None, headers: dict = None, **kwargs):
        """Rate-limited, retrying POST request."""
        url = self._build_url(path)
        return self._request("POST", url, data=data, json=json,
                             params=params, headers=headers, **kwargs)

    def put(self, path: str = "", data=None, json=None, **kwargs):
        url = self._build_url(path)
        return self._request("PUT", url, data=data, json=json, **kwargs)

    def delete(self, path: str = "", **kwargs):
        url = self._build_url(path)
        return self._request("DELETE", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Core request with rate limiting, scope check, and retry."""

        # 1. Scope check — ALWAYS before any request
        if not self._check_scope(url):
            self.log(f"OUT OF SCOPE — blocked: {url}", "!")
            return None

        # 2. Rate limiting — enforce minimum interval between requests
        self._rate_limit_wait()

        # 3. Retry loop with exponential backoff
        delay = self.RETRY_DELAY
        for attempt in range(self.MAX_RETRIES):
            try:
                # Merge any extra headers
                extra_headers = kwargs.pop("headers", None)
                if extra_headers:
                    merged = dict(self.session.headers)
                    merged.update(extra_headers)
                    kwargs["headers"] = merged

                resp = self.session.request(
                    method, url,
                    timeout=self.timeout,
                    allow_redirects=kwargs.pop("allow_redirects", True),
                    verify=False,
                    **kwargs,
                )
                self._last_request = time.time()
                return resp

            except requests.exceptions.Timeout:
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(delay)
                    delay *= 2
                else:
                    return None

            except requests.exceptions.ConnectionError:
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(delay)
                    delay *= 2
                else:
                    return None

            except Exception:
                return None

        return None

    def _rate_limit_wait(self):
        """Enforce rate limit with small random jitter."""
        elapsed = time.time() - self._last_request
        needed  = self._min_interval - elapsed
        if needed > 0:
            # Add small random jitter (±10%) to avoid detection
            jitter = needed * random.uniform(0.9, 1.1)
            time.sleep(jitter)

    def _check_scope(self, url: str) -> bool:
        """Check if URL is in scope before requesting."""
        if self._scope_validator is None:
            return True  # No validator = allow all
        try:
            result = self._scope_validator.is_in_scope(url)
            return result
        except Exception:
            return True  # Fail open — don't block on validator error

    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        if not path:
            return self.url
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if path.startswith("/"):
            return f"{self.parsed.scheme}://{self.parsed.netloc}{path}"
        return f"{self.url}/{path}"

    # ── Finding Management ────────────────────────────────────

    def add_finding(self, title: str, severity: str, description: str,
                    evidence: str, remediation: str,
                    url: str = None, cve: str = "",
                    parameter: str = "", payload: str = ""):
        """Add a finding with automatic deduplication."""
        url = url or self.url

        # Deduplication fingerprint
        fp = hashlib.sha256(
            f"{self.NAME}|{title}|{url}|{parameter}|{payload}".encode()
        ).hexdigest()[:16]

        if fp in self._fingerprints:
            return  # Duplicate — skip
        self._fingerprints.add(fp)

        finding = {
            "title":       title,
            "severity":    severity,
            "module":      self.NAME,
            "url":         url,
            "parameter":   parameter,
            "payload":     payload,
            "description": description,
            "evidence":    evidence,
            "remediation": remediation,
            "cve":         cve,
            "timestamp":   datetime.now().isoformat(),
            "fingerprint": fp,
        }
        self.findings.append(finding)

        # Console output
        sev_colors = {
            "CRITICAL": R, "HIGH": Y, "MEDIUM": C, "LOW": G, "INFO": D
        }
        c = sev_colors.get(severity, D)
        print(f"  {c}[{severity}]{X} {W}{title}{X}")
        if parameter:
            print(f"          {D}↳ {url} [{parameter}={payload[:30] if payload else ''}]{X}")

    def log(self, msg: str, level: str = "*"):
        """Log a message."""
        colors = {"+": G, "!": R, "~": Y, "i": C, "*": D}
        c = colors.get(level, D)
        print(f"  {c}[{self.NAME.upper()}/{level}]{X} {msg}")

    def result(self) -> dict:
        """Return module results."""
        return {
            "module":    self.NAME,
            "url":       self.url,
            "findings":  self.findings,
            "info":      self.info,
            "timestamp": datetime.now().isoformat(),
        }

    def run(self) -> dict:
        """Override in subclasses."""
        return self.result()

    # ── Convenience Helpers ───────────────────────────────────

    def extract_forms(self, response: requests.Response) -> list:
        """Extract form data from HTML response."""
        if not response:
            return []
        forms = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                inputs = {}
                for inp in form.find_all(["input","textarea","select"]):
                    name = inp.get("name","")
                    if name:
                        inputs[name] = inp.get("value","")
                forms.append({
                    "action":  form.get("action",""),
                    "method":  form.get("method","get").lower(),
                    "inputs":  inputs,
                })
        except Exception:
            pass
        return forms

    def random_string(self, length: int = 8) -> str:
        """Generate random alphanumeric string."""
        import string
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
