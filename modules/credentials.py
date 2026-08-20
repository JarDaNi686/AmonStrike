"""
AmonStrike — Credential Engine
Discovered credentials → test across all services.
Password spraying, credential stuffing, hash cracking guidance.
"""

import re
import socket
import requests
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule


class CredentialModule(BaseModule):
    NAME        = "credentials"
    DESCRIPTION = "Credential testing — stuffing, spraying, hash identification"

    # Default credential pairs to test
    DEFAULT_CREDS = [
        ("admin",         "admin"),
        ("admin",         "password"),
        ("admin",         "admin123"),
        ("admin",         "123456"),
        ("admin",         "Password1"),
        ("admin",         ""),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("root",          "root"),
        ("root",          "toor"),
        ("root",          "password"),
        ("test",          "test"),
        ("guest",         "guest"),
        ("demo",          "demo"),
        ("user",          "user"),
        ("admin",         "admin@123"),
        ("admin",         "Admin@123"),
        ("superadmin",    "superadmin"),
        ("sa",            "sa"),
        ("postgres",      "postgres"),
        ("mysql",         "mysql"),
    ]

    # Service-specific default credentials
    SERVICE_DEFAULTS = {
        "mysql":     [("root",""), ("root","root"), ("mysql","mysql")],
        "postgres":  [("postgres","postgres"), ("postgres","")],
        "redis":     [("",""), ("admin","admin")],
        "mongodb":   [("admin","admin"), ("","")],
        "ftp":       [("anonymous","anonymous"), ("ftp","ftp"), ("admin","admin")],
        "ssh":       [("root","root"), ("admin","admin"), ("ubuntu","ubuntu")],
        "jenkins":   [("admin","admin"), ("jenkins","jenkins")],
        "tomcat":    [("admin","admin"), ("tomcat","tomcat"), ("admin","tomcat")],
        "phpmyadmin":[("root",""), ("root","root"), ("admin","admin")],
        "kibana":    [("elastic","elastic"), ("kibana","kibana")],
        "grafana":   [("admin","admin")],
    }

    # Hash patterns for identification
    HASH_PATTERNS = {
        "MD5":     r"^[a-f0-9]{32}$",
        "SHA1":    r"^[a-f0-9]{40}$",
        "SHA256":  r"^[a-f0-9]{64}$",
        "SHA512":  r"^[a-f0-9]{128}$",
        "bcrypt":  r"^\$2[aby]\$\d{2}\$.{53}$",
        "NTLM":    r"^[a-f0-9]{32}:[a-f0-9]{32}$",
        "MySQL":   r"^\*[A-F0-9]{40}$",
    }

    def run(self):
        self.log("Starting credential engine...")

        # Discover login endpoints
        login_endpoints = self._discover_login_endpoints()
        self.info["login_endpoints"] = login_endpoints

        if login_endpoints:
            self.log(f"Found {len(login_endpoints)} login endpoints", "i")
            # Test default credentials
            self._test_default_credentials(login_endpoints)
            # Check for password reset vulnerabilities
            self._check_password_reset()
        else:
            self.log("No login endpoints found", "~")

        # Check exposed hashes or credentials in responses
        self._check_exposed_credentials()

        # Test open ports for default service credentials
        self._test_service_credentials()

        # Check for credential in URL parameters
        self._check_credentials_in_url()

        self.log(f"Credential engine complete — {len(self.findings)} findings", "+")
        return self.result()

    def _discover_login_endpoints(self):
        """Find login pages and API auth endpoints."""
        login_paths = [
            "/login", "/signin", "/auth", "/authenticate",
            "/admin/login", "/admin", "/wp-login.php",
            "/user/login", "/account/login", "/session/new",
            "/api/auth", "/api/login", "/api/token",
            "/api/v1/auth", "/api/v1/login",
            "/oauth/token", "/oauth2/token",
            "/panel", "/dashboard", "/administrator",
            "/phpmyadmin", "/pma",
        ]

        found = []
        for path in login_paths:
            r = self.get(path)
            if r and r.status_code in [200, 301, 302]:
                # Check if it's actually a login page
                if any(s in r.text.lower() for s in
                       ["password", "login", "signin", "username", "email"]):
                    found.append({
                        "url":    self.url + path,
                        "path":   path,
                        "status": r.status_code,
                    })

        return found

    def _test_default_credentials(self, endpoints):
        """Test default credentials on discovered login endpoints."""
        for endpoint in endpoints[:3]:  # Limit endpoints
            url     = endpoint["url"]
            path    = endpoint["path"]

            # Get the login page to extract form details
            r = self.get(path)
            if not r:
                continue

            # Extract form fields
            from bs4 import BeautifulSoup
            try:
                soup   = BeautifulSoup(r.text, "html.parser")
                forms  = soup.find_all("form")
                if not forms:
                    continue

                form   = forms[0]
                action = form.get("action", path)
                method = form.get("method", "post").lower()

                # Get input names
                inputs = {}
                for inp in form.find_all("input"):
                    name  = inp.get("name", "")
                    itype = inp.get("type", "text").lower()
                    if name:
                        inputs[name] = inp.get("value", "")

                # Identify username/password fields
                user_field = self._identify_field(inputs, ["user","email","login","name"])
                pass_field = self._identify_field(inputs, ["pass","pwd","secret","key"])

                if not user_field or not pass_field:
                    continue

                # Test credentials with rate limiting awareness
                success_found = False
                for username, password in self.DEFAULT_CREDS[:10]:
                    if success_found:
                        break

                    test_data = dict(inputs)
                    test_data[user_field] = username
                    test_data[pass_field] = password

                    # Add CSRF token if present
                    csrf_field = self._identify_field(inputs, ["csrf","token","nonce"])
                    if csrf_field:
                        test_data[csrf_field] = inputs.get(csrf_field, "")

                    submit_url = self.url + action if action.startswith("/") else url

                    if method == "post":
                        resp = self.post(submit_url.replace(self.url, ""), data=test_data)
                    else:
                        resp = self.get(submit_url.replace(self.url, ""), params=test_data)

                    if not resp:
                        continue

                    # Detect successful login
                    if self._is_login_success(resp, username):
                        success_found = True
                        self.add_finding(
                            title=f"Default Credentials Work: {username}/{password}",
                            severity="CRITICAL",
                            description=f"Default credentials '{username}/{password}' successfully authenticate at {url}.",
                            evidence=f"URL: {url}\nCredentials: {username}/{password}\nResponse: HTTP {resp.status_code}",
                            remediation="Change default credentials immediately. Enforce strong password policy. Implement MFA.",
                            url=url,
                            cve="CWE-798"
                        )

                    # Check for account lockout
                    if resp.status_code == 429 or "locked" in resp.text.lower():
                        self.log(f"Account lockout triggered at {url}", "+")
                        break

                    import time
                    time.sleep(0.5)  # Avoid triggering lockout

            except ImportError:
                self.log("BeautifulSoup not available for form parsing", "~")
            except Exception as e:
                self.log(f"Credential test error: {e}", "~")

    def _identify_field(self, inputs, keywords):
        """Find a form field matching keywords."""
        for key in inputs:
            for kw in keywords:
                if kw.lower() in key.lower():
                    return key
        return None

    def _is_login_success(self, resp, username):
        """Detect successful login from response."""
        # Success indicators
        success_signs = [
            "dashboard", "welcome", "logout", "sign out",
            "profile", "account", "hello", f"hello {username}",
            "settings", "administration", "panel"
        ]
        failure_signs = [
            "invalid", "incorrect", "wrong", "failed",
            "error", "try again", "doesn't match"
        ]

        text_lower = resp.text.lower()

        # Check failure signs first
        if any(s in text_lower for s in failure_signs):
            return False

        # Check success signs
        if any(s in text_lower for s in success_signs):
            return True

        # Check redirect to dashboard
        if resp.status_code in [301, 302]:
            location = resp.headers.get("Location", "")
            if any(s in location.lower() for s in ["dashboard","admin","panel","home"]):
                return True

        return False

    def _check_password_reset(self):
        """Check for password reset vulnerabilities."""
        reset_paths = ["/forgot-password", "/reset-password",
                      "/password/reset", "/user/password"]

        for path in reset_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Check for username enumeration in reset
            resp_valid = self.post(path, data={
                "email": "admin@" + self.parsed.hostname,
                "username": "admin"
            })
            resp_invalid = self.post(path, data={
                "email": "nonexistent_xyz_123@" + self.parsed.hostname,
                "username": "nonexistent_xyz_123"
            })

            if resp_valid and resp_invalid:
                # Different responses = user enumeration
                if len(resp_valid.text) != len(resp_invalid.text):
                    self.add_finding(
                        title=f"Username Enumeration via Password Reset: {path}",
                        severity="MEDIUM",
                        description="Password reset form returns different responses for valid vs invalid usernames, enabling account enumeration.",
                        evidence=f"Valid user response length: {len(resp_valid.text)}\nInvalid user response length: {len(resp_invalid.text)}",
                        remediation="Return identical responses for both valid and invalid email/username in password reset flow.",
                        url=self.url + path,
                        cve="CWE-204"
                    )

    def _check_exposed_credentials(self):
        """Look for exposed credentials in responses."""
        resp = self.get()
        if not resp:
            return

        # Patterns that indicate exposed credentials
        cred_patterns = [
            (r'password\s*=\s*["\']([^"\']{4,})["\']', "Password in source"),
            (r'passwd\s*=\s*["\']([^"\']{4,})["\']',   "Password in source"),
            (r'api_key\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key in source"),
            (r'secret\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']',  "Secret in source"),
            (r'token\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']',   "Token in source"),
            (r'(AKIA[0-9A-Z]{16})',                              "AWS Access Key"),
        ]

        for pattern, label in cred_patterns:
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            if matches:
                self.add_finding(
                    title=f"Credentials Exposed in Source: {label}",
                    severity="CRITICAL",
                    description=f"{label} found in page source code.",
                    evidence=f"Pattern: {label}\nFound: {matches[0][:20]}...",
                    remediation="Remove credentials from source code immediately. Use environment variables or secrets managers.",
                    url=self.url,
                    cve="CWE-312"
                )

        # Check for hashes that might be crackable
        hash_patterns = [
            (r"[a-f0-9]{32}", "MD5 hash"),
            (r"[a-f0-9]{40}", "SHA1 hash"),
            (r"\$2[aby]\$\d{2}\$.{53}", "bcrypt hash"),
        ]
        for pattern, label in hash_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                self.add_finding(
                    title=f"Password Hash Exposed: {label}",
                    severity="HIGH",
                    description=f"A {label} was found in the page response. This may be a crackable password hash.",
                    evidence=f"Hash type: {label}\nFound in response body",
                    remediation="Never expose password hashes in HTTP responses. Use proper session management.",
                    url=self.url,
                    cve="CWE-312"
                )

    def _test_service_credentials(self):
        """Test default credentials on discovered open services."""
        host = self.parsed.hostname

        # Check common service ports
        services_to_check = {
            21:   "ftp",
            22:   "ssh",
            3306: "mysql",
            5432: "postgres",
            6379: "redis",
            27017: "mongodb",
        }

        for port, service in services_to_check.items():
            if not self._port_open(host, port):
                continue

            self.log(f"Testing {service} credentials on port {port}...", "i")
            creds = self.SERVICE_DEFAULTS.get(service, [])

            for username, password in creds:
                if self._test_service_login(service, host, port, username, password):
                    self.add_finding(
                        title=f"Default {service.upper()} Credentials: {username}/{password or '(empty)'}",
                        severity="CRITICAL",
                        description=f"Default credentials work for {service} on port {port}.",
                        evidence=f"Service: {service}\nHost: {host}:{port}\nCredentials: {username}/{password or '(empty)'}",
                        remediation=f"Change default {service} credentials immediately. Restrict {service} access to trusted IPs only.",
                        url=f"{service}://{host}:{port}",
                        cve="CWE-798"
                    )
                    break

    def _port_open(self, host, port):
        """Quick port check."""
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
            return True
        except Exception:
            return False

    def _test_service_login(self, service, host, port, username, password):
        """Test credentials for a specific service."""
        try:
            if service == "ftp":
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=5)
                ftp.login(username, password)
                ftp.quit()
                return True

            elif service == "redis":
                import socket
                s = socket.create_connection((host, port), timeout=3)
                if password:
                    s.send(f"AUTH {password}\r\n".encode())
                else:
                    s.send(b"PING\r\n")
                resp = s.recv(100).decode()
                s.close()
                return "+OK" in resp or "+PONG" in resp

        except Exception:
            pass
        return False

    def _check_credentials_in_url(self):
        """Check if credentials appear in URL parameters."""
        resp = self.get()
        if not resp:
            return

        # Check current URL for credentials
        url = resp.url
        if any(s in url.lower() for s in ["password=", "passwd=", "pwd=", "pass="]):
            self.add_finding(
                title="Credentials in URL Parameters",
                severity="HIGH",
                description="Password or credentials found in URL parameters. These are logged by servers, proxies, and browser history.",
                evidence=f"URL contains credential parameter: {url[:100]}",
                remediation="Never pass credentials in URL parameters. Use POST requests with HTTPS body.",
                url=url,
                cve="CWE-598"
            )

    def identify_hash(self, hash_str):
        """Identify hash type from string."""
        for hash_type, pattern in self.HASH_PATTERNS.items():
            if re.match(pattern, hash_str.strip(), re.IGNORECASE):
                return hash_type
        return "Unknown"
