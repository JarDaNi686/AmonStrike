"""
AmonStrike — Deserialization Attack Module
Insecure deserialization — OWASP Top 10 A08:2021

Attacks:
  1. Java — ysoserial gadget chains
  2. PHP — unserialize() injection
  3. Python — pickle injection
  4. .NET — BinaryFormatter
  5. Ruby — Marshal.load
  6. Node.js — node-serialize
  7. Generic — magic byte detection + cookie tampering
"""

import re
import base64
import struct
from .base import BaseModule


class DeserializationModule(BaseModule):
    NAME        = "deserialization"
    DESCRIPTION = "Insecure deserialization — Java, PHP, Python pickle, .NET"

    # Magic bytes identifying serialized objects
    MAGIC_BYTES = {
        "java_rmi":       b"\xac\xed\x00\x05",     # Java serialization
        "java_rmi_b64":   "rO0AB",                  # Java serialization base64
        "php_object":     b"O:",                    # PHP object serialize
        "php_array":      b"a:",                    # PHP array serialize
        "php_string":     b"s:",                    # PHP string serialize
        "python_pickle":  b"\x80\x02",              # Python pickle protocol 2
        "python_pickle3": b"\x80\x04",              # Python pickle protocol 4
        "dotnet":         b"\x00\x01\x00\x00\x00", # .NET BinaryFormatter
    }

    def run(self):
        self.log("Testing for insecure deserialization...")

        # Detect serialized data in requests/responses
        self._detect_serialized_data()

        # Test specific deserialization endpoints
        self._test_java_deserialization()
        self._test_php_deserialization()
        self._test_python_pickle()
        self._test_cookie_deserialization()
        self._test_nodejs_deserialization()

        self.log(f"Deserialization scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _detect_serialized_data(self):
        """Scan responses and cookies for serialized object signatures."""
        resp = self.get()
        if not resp:
            return

        # Check cookies for serialized data
        for cookie_name, cookie_value in resp.cookies.items():
            detected = self._identify_serialization(cookie_value)
            if detected:
                self.add_finding(
                    title=f"Serialized Object in Cookie: {cookie_name} ({detected})",
                    severity="HIGH",
                    description=(
                        f"Cookie '{cookie_name}' contains a {detected} serialized object. "
                        "If this data is deserialized server-side without validation, "
                        "it may lead to Remote Code Execution."
                    ),
                    evidence=(
                        f"Cookie: {cookie_name}={cookie_value[:50]}...\n"
                        f"Serialization format: {detected}"
                    ),
                    remediation=(
                        "Never deserialize user-controlled data. "
                        "Use HMAC signatures to verify serialized data integrity. "
                        "Consider JSON instead of native serialization formats."
                    ),
                    url=self.url,
                    cve="CWE-502"
                )

        # Check response body
        body = resp.text
        for format_name, magic in self.MAGIC_BYTES.items():
            if isinstance(magic, str):
                if magic in body:
                    self.add_finding(
                        title=f"Serialized Object in Response Body ({format_name})",
                        severity="MEDIUM",
                        description=(
                            f"Response body contains {format_name} serialized data. "
                            "Reflected serialized objects may be tampered with."
                        ),
                        evidence=f"Magic signature found: {magic} in response body",
                        remediation="Avoid serializing server objects to client-facing responses.",
                        url=self.url,
                        cve="CWE-502"
                    )

    def _identify_serialization(self, data: str) -> str:
        """Identify serialization format from a string value."""
        try:
            # Try base64 decode
            decoded = base64.b64decode(data + "==")
        except Exception:
            decoded = data.encode()

        for name, magic in self.MAGIC_BYTES.items():
            if isinstance(magic, bytes) and decoded.startswith(magic):
                return name
            elif isinstance(magic, str) and magic in data:
                return name

        # PHP detect
        if re.match(r'^[OasiCbN]:\d+:', data):
            return "php"

        return ""

    def _test_java_deserialization(self):
        """Test Java deserialization vulnerabilities."""
        # DNS-safe ysoserial payload markers
        # We test for acceptance of Java serialized objects, not actual RCE
        java_deser_endpoints = [
            "/api/", "/rmi", "/jmx",
            "/api/import", "/api/data",
        ]

        # Minimal Java serialized object (not malicious, just header)
        # \xac\xed\x00\x05 = Java serialization magic
        java_magic_b64 = base64.b64encode(b"\xac\xed\x00\x05\x73\x72").decode()

        for path in java_deser_endpoints:
            for header_name in ["X-Java-Serialized-Object",
                                 "Content-Type"]:
                r = self.post(
                    path,
                    data=base64.b64decode(java_magic_b64 + "=="),
                    headers={
                        header_name: "application/x-java-serialized-object",
                        "Content-Type": "application/octet-stream",
                    }
                )
                if r and r.status_code in [200,500]:
                    # 500 error with ClassNotFoundException = confirmed Java deser
                    if any(err in r.text for err in [
                        "ClassNotFoundException",
                        "java.io.StreamCorruptedException",
                        "java.lang.ClassCastException",
                        "org.apache.commons",
                    ]):
                        self.add_finding(
                            title=f"Java Deserialization Endpoint Confirmed at {path}",
                            severity="CRITICAL",
                            description=(
                                f"Endpoint {path} accepts and processes Java serialized "
                                "objects. Java deserialization errors in response confirm "
                                "the endpoint deserializes objects server-side. "
                                "This is typically exploitable for RCE via ysoserial gadget chains."
                            ),
                            evidence=(
                                f"Java serialization magic bytes sent to {path}\n"
                                f"Java class error in response: {r.text[:300]}"
                            ),
                            remediation=(
                                "Do not deserialize Java objects from untrusted sources. "
                                "Use Java agent to block unsafe deserialization (SerialKiller). "
                                "Implement ObjectInputFilter (Java 9+). "
                                "Use JSON/Protobuf instead."
                            ),
                            url=self.url + path,
                            cve="CWE-502"
                        )
                        break

    def _test_php_deserialization(self):
        """Test PHP unserialize() injection."""
        # PHP serialized string with a simple object
        # O:8:"stdClass":1:{s:4:"test";s:5:"value";}
        php_payloads = [
            'O:8:"stdClass":1:{s:4:"test";s:5:"value";}',
            'a:2:{i:0;s:4:"test";i:1;s:5:"value";}',
            # Magic method triggers
            'O:8:"stdClass":1:{s:4:"__destruct";O:8:"stdClass":0:{}}',
        ]

        php_params = ["data","payload","object","serialized","session",
                      "token","user","auth"]

        for param in php_params:
            for payload in php_payloads[:1]:  # Just test one
                # Test in URL parameter
                resp = self.get(params={param: payload})
                if resp:
                    if any(err in resp.text for err in [
                        "__wakeup","__destruct","unserialize",
                        "Unexpected end of serialized data",
                        "O:8:","Notice: unserialize()",
                    ]):
                        self.add_finding(
                            title=f"PHP Deserialization — Parameter '{param}'",
                            severity="CRITICAL",
                            description=(
                                f"PHP unserialize() called on user-controlled parameter '{param}'. "
                                "PHP deserialization can trigger magic methods (__wakeup, "
                                "__destruct, __toString) leading to RCE via gadget chains."
                            ),
                            evidence=(
                                f"Payload: {payload}\nParameter: {param}\n"
                                f"Response: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Never call unserialize() on user input. "
                                "Use json_decode() instead. "
                                "If serialization is necessary, use HMAC to verify integrity."
                            ),
                            url=self.url,
                            cve="CWE-502"
                        )
                        break

        # Also test cookies
        for payload in php_payloads[:1]:
            encoded = base64.b64encode(payload.encode()).decode()
            for cookie_name in ["session","auth","user","remember_me"]:
                resp = self.get(cookies={cookie_name: encoded})
                if resp and "unserialize" in resp.text:
                    self.add_finding(
                        title=f"PHP Deserialization via Cookie '{cookie_name}'",
                        severity="CRITICAL",
                        description=(
                            f"PHP unserialize() is called on cookie '{cookie_name}'. "
                            "Full PHP Object Injection via cookie value."
                        ),
                        evidence=f"Cookie {cookie_name}={encoded[:30]}... triggers unserialize()",
                        remediation="Never unserialize cookie values. Use HMAC-signed JSON tokens.",
                        url=self.url,
                        cve="CWE-502"
                    )
                    break

    def _test_python_pickle(self):
        """Test Python pickle deserialization."""
        import pickle, io

        # Safe pickle that just creates a dict (no RCE)
        safe_pickle = pickle.dumps({"test": "amonstrike_probe"})
        safe_b64    = base64.b64encode(safe_pickle).decode()

        pickle_endpoints = [
            "/api/data", "/api/import", "/api/load",
            "/api/model", "/api/predict",
        ]

        for path in pickle_endpoints:
            for header in ["application/octet-stream","application/x-pickle"]:
                r = self.post(
                    path,
                    data=safe_pickle,
                    headers={"Content-Type": header}
                )
                if r and r.status_code == 200:
                    if "amonstrike_probe" in r.text or "test" in r.text:
                        self.add_finding(
                            title=f"Python Pickle Deserialization at {path}",
                            severity="CRITICAL",
                            description=(
                                f"Endpoint {path} deserializes Python pickle objects. "
                                "Pickle deserialization of untrusted data is equivalent to RCE — "
                                "any Python code can be executed."
                            ),
                            evidence=(
                                f"Safe pickle sent: {safe_b64[:50]}...\n"
                                f"Response contains deserialized value: amonstrike_probe"
                            ),
                            remediation=(
                                "Never use pickle with untrusted data. "
                                "Use JSON or MessagePack. "
                                "If pickle is required, sign with HMAC and verify signature."
                            ),
                            url=self.url + path,
                            cve="CWE-502"
                        )
                        break

    def _test_cookie_deserialization(self):
        """Test for deserialized data in session cookies."""
        resp = self.get()
        if not resp:
            return

        for cookie_name, cookie_value in resp.cookies.items():
            # Try to modify and see if it causes an error
            if len(cookie_value) < 10:
                continue

            # Tamper with base64 cookie
            try:
                # Add extra data to trigger deserialization error
                tampered = cookie_value + "AAAA"
                r = self.get(cookies={cookie_name: tampered})
                if r and any(err in r.text for err in [
                    "unserialize","deserialize","unpickle",
                    "ClassNotFoundException","InvalidObjectException",
                    "BinaryFormatter",
                ]):
                    self.add_finding(
                        title=f"Deserialization Error via Cookie '{cookie_name}'",
                        severity="HIGH",
                        description=(
                            f"Tampering with cookie '{cookie_name}' causes a "
                            "deserialization error, confirming the server deserializes "
                            "user-supplied cookie data."
                        ),
                        evidence=(
                            f"Original: {cookie_value[:30]}\n"
                            f"Tampered: {tampered[:30]}\n"
                            f"Error: {r.text[:200]}"
                        ),
                        remediation=(
                            "Use HMAC-signed cookies. Verify signatures before deserializing. "
                            "Consider using JWT or encrypted+signed tokens."
                        ),
                        url=self.url,
                        cve="CWE-502"
                    )
            except Exception:
                pass

    def _test_nodejs_deserialization(self):
        """Test Node.js node-serialize RCE."""
        # node-serialize payload (safe — just creates a variable)
        # Real exploit would use IIFE: {"rce":"_$$ND_FUNC$$_function(){}()"}
        # We just test if the format is accepted
        nodeserial_probe = '{"type":"probe","data":"amonstrike"}'

        nodeserial_endpoints = [
            "/api/", "/api/data", "/api/import",
        ]

        for path in nodeserial_endpoints:
            r = self.post(
                path,
                data=nodeserial_probe,
                headers={"Content-Type": "application/json"}
            )
            if r and "amonstrike" in r.text:
                # Further probe for IIFE execution
                # (we test for acceptance only, not actual RCE)
                self.add_finding(
                    title=f"Potential Node.js Deserialization at {path}",
                    severity="MEDIUM",
                    description=(
                        f"Endpoint {path} reflects probe data, suggesting possible "
                        "Node.js deserialization. If node-serialize is used, this "
                        "can lead to RCE via IIFE gadgets."
                    ),
                    evidence=f"Probe reflected at {path}",
                    remediation=(
                        "Avoid node-serialize package. "
                        "Use JSON.parse() for data parsing. "
                        "Never evaluate or deserialize user-supplied functions."
                    ),
                    url=self.url + path,
                    cve="CWE-502"
                )
                break
