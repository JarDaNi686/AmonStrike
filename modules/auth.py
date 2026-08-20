"""AmonStrike — Authentication Testing Module"""
import re
import base64
from .base import BaseModule

class AuthModule(BaseModule):
    NAME = "auth"
    DESCRIPTION = "Authentication — default creds, JWT, session, brute-force indicators"

    DEFAULT_CREDS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("admin", "admin123"), ("admin", ""), ("root", "root"),
        ("root", "password"), ("test", "test"), ("guest", "guest"),
        ("user", "user"), ("admin", "Admin"), ("administrator", "administrator"),
    ]

    def run(self):
        self.log("Testing authentication mechanisms...")
        resp = self.get()
        if not resp:
            return self.result()

        self._check_login_page(resp)
        self._check_jwt_tokens(resp)
        self._check_http_auth()
        self._check_default_creds()
        self._check_password_policy(resp)

        self.log(f"Auth scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _check_login_page(self, resp):
        """Find login pages."""
        login_paths = ["/login", "/signin", "/auth", "/user/login", "/admin/login", "/wp-login.php"]
        for path in login_paths:
            r = self.get(path)
            if r and r.status_code == 200 and any(s in r.text.lower() for s in ["password", "login", "signin"]):
                self.info["login_page"] = self.url + path
                self.log(f"Login page found: {path}", "i")

                # Check for lockout protection
                self._check_rate_limiting(path)
                break

    def _check_rate_limiting(self, login_path):
        """Check if login is rate-limited (brute-force protection)."""
        responses = []
        for i in range(6):
            r = self.post(login_path, data={"username": f"test{i}", "password": "wrongpassword"})
            if r:
                responses.append(r.status_code)

        if len(set(responses)) == 1 and responses[0] in [200, 401]:
            self.add_finding(
                title="No Rate Limiting on Login — Brute-Force Risk",
                severity="HIGH",
                description="Login endpoint does not appear to rate-limit failed attempts. Brute-force attacks are possible.",
                evidence=f"6 consecutive failed login attempts all returned HTTP {responses[0]} without delay or lockout.",
                remediation="Implement rate limiting, account lockout after N failed attempts, CAPTCHA, and IP-based throttling.",
                url=self.url + login_path,
                cve="CWE-307"
            )

    def _check_jwt_tokens(self, resp):
        """Check JWT tokens in cookies and headers."""
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

        # Check cookies
        for cookie in resp.cookies:
            if re.match(jwt_pattern, cookie.value):
                self._analyze_jwt(cookie.value, f"Cookie: {cookie.name}")

        # Check response body
        matches = re.findall(jwt_pattern, resp.text)
        for jwt in matches[:3]:
            self._analyze_jwt(jwt, "Response body")

    def _analyze_jwt(self, token, location):
        """Analyze JWT token for weaknesses."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode header
            header_b64 = parts[0] + "=="
            header = base64.b64decode(header_b64.encode()).decode("utf-8", errors="ignore")

            # Check for none algorithm
            if '"alg":"none"' in header or '"alg": "none"' in header:
                self.add_finding(
                    title="JWT Algorithm None Attack",
                    severity="CRITICAL",
                    description="JWT uses 'none' algorithm. Signature verification is disabled.",
                    evidence=f"Location: {location}\nHeader: {header}",
                    remediation="Always verify JWT signature. Reject tokens with 'none' algorithm. Use strong algorithms (RS256, ES256).",
                    url=self.url,
                    cve="CWE-347"
                )
            elif '"alg":"HS256"' in header:
                self.add_finding(
                    title="JWT Uses Weak Algorithm (HS256)",
                    severity="LOW",
                    description="JWT uses HS256 (HMAC-SHA256) symmetric algorithm. If the secret is weak, tokens can be forged.",
                    evidence=f"Location: {location}\nAlgorithm: HS256",
                    remediation="Use asymmetric algorithms (RS256, ES256). Ensure HS256 secret is cryptographically random and at least 256 bits.",
                    url=self.url,
                    cve="CWE-347"
                )

            # Decode payload for sensitive data
            payload_b64 = parts[1] + "=="
            payload = base64.b64decode(payload_b64.encode()).decode("utf-8", errors="ignore")
            self.info["jwt_payload_sample"] = payload[:200]

        except Exception:
            pass

    def _check_http_auth(self):
        """Check for HTTP Basic Auth protected areas."""
        r = self.get()
        if r and r.status_code == 401:
            auth_header = r.headers.get("WWW-Authenticate", "")
            if "Basic" in auth_header:
                self.add_finding(
                    title="HTTP Basic Authentication Detected",
                    severity="MEDIUM",
                    description="HTTP Basic Authentication is used. Credentials are Base64 encoded (not encrypted) and easily decoded.",
                    evidence=f"WWW-Authenticate: {auth_header}",
                    remediation="Use form-based authentication with HTTPS. Avoid HTTP Basic Auth unless over HTTPS with additional controls.",
                    url=self.url
                )

    def _check_default_creds(self):
        """Try common default credentials on discovered login pages."""
        login_path = self.info.get("login_page", "").replace(self.url, "") or "/login"
        r = self.get(login_path)
        if not r or r.status_code == 404:
            return

        for username, password in self.DEFAULT_CREDS[:5]:  # Limit attempts
            data = {"username": username, "password": password,
                    "user": username, "pass": password, "email": username}
            resp = self.post(login_path, data=data)
            if resp and resp.status_code in [200, 302]:
                # Check for successful login indicators
                if any(s in resp.text.lower() for s in ["dashboard", "welcome", "logout", "profile", "account"]):
                    self.add_finding(
                        title=f"Default Credentials Work: {username}/{password}",
                        severity="CRITICAL",
                        description=f"Default credentials {username}/{password} successfully authenticated.",
                        evidence=f"POST {login_path}\nCredentials: {username}/{password}\nResponse: {resp.status_code}",
                        remediation="Change all default credentials immediately. Force password change on first login. Implement strong password policy.",
                        url=self.url + login_path,
                        cve="CWE-798"
                    )

    def _check_password_policy(self, resp):
        """Check password policy indicators in registration/reset forms."""
        policy_paths = ["/register", "/signup", "/forgot-password", "/reset-password"]
        for path in policy_paths:
            r = self.get(path)
            if r and r.status_code == 200:
                # Look for password requirements
                if not re.search(r'(minimum|at least|must contain|character|uppercase|lowercase|number|special)', r.text, re.I):
                    self.add_finding(
                        title="No Password Policy Enforced",
                        severity="MEDIUM",
                        description=f"No password complexity requirements found at {path}.",
                        evidence=f"GET {path} → {r.status_code}. No password policy indicators in page.",
                        remediation="Enforce minimum password length (12+ chars), complexity requirements, and check against known breached passwords.",
                        url=self.url + path,
                        cve="CWE-521"
                    )
                    break
