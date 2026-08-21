"""
AmonStrike — Reconnaissance Module
Gathers: headers, tech stack, SSL, DNS, WHOIS, robots.txt, sitemap
"""

import ssl
import socket
import re
from urllib.parse import urlparse
from .base import BaseModule


class ReconModule(BaseModule):
    NAME        = "recon"
    DESCRIPTION = "Reconnaissance — tech stack, headers, DNS, SSL, sitemap"

    # Technology fingerprints
    TECH_SIGNATURES = {
        "WordPress":   ["wp-content", "wp-includes", "WordPress"],
        "Drupal":      ["Drupal", "drupal.js", "sites/default"],
        "Joomla":      ["Joomla", "/components/com_"],
        "Laravel":     ["laravel_session", "Laravel"],
        "Django":      ["csrfmiddlewaretoken", "django"],
        "Flask":       ["Werkzeug", "flask"],
        "Express":     ["X-Powered-By: Express"],
        "Spring":      ["X-Application-Context", "Spring"],
        "ASP.NET":     ["X-AspNet-Version", "ASP.NET", "__VIEWSTATE"],
        "PHP":         ["X-Powered-By: PHP", ".php"],
        "Ruby/Rails":  ["X-Runtime", "_rails_"],
        "Angular":     ["ng-version", "angular"],
        "React":       ["__REACT", "react-root", "_next"],
        "Vue.js":      ["__vue__", "vue.js"],
        "jQuery":      ["jquery", "jQuery"],
        "Bootstrap":   ["bootstrap.css", "bootstrap.js"],
        "nginx":       ["Server: nginx"],
        "Apache":      ["Server: Apache"],
        "IIS":         ["Server: Microsoft-IIS"],
        "Cloudflare":  ["CF-RAY", "cloudflare"],
        "MySQL":       ["MySQL", "mysql_"],
        "PostgreSQL":  ["PostgreSQL", "psql"],
        "MongoDB":     ["MongoDB", "mongo"],
    }

    def run(self):
        self.log("Starting reconnaissance...")

        # Basic request
        resp = self.get()
        if not resp:
            self.log("Cannot reach target", "!")
            return self.result()

        self.info["status_code"]   = resp.status_code
        self.info["response_time"] = f"{resp.elapsed.total_seconds():.3f}s"
        self.info["final_url"]     = resp.url
        self.info["headers"]       = dict(resp.headers)

        self._check_headers(resp)
        self._detect_tech(resp)
        self._check_ssl()
        self._check_dns()
        self._check_robots()
        self._check_sitemap()
        self._check_security_txt()
        self._check_common_files(resp)

        self.log(f"Recon complete — {len(self.findings)} findings", "+")
        return self.result()

    def _check_headers(self, resp):
        """Analyze response headers for information disclosure."""
        headers = resp.headers

        # Server header disclosure
        server = headers.get("Server", "")
        if server:
            self.info["server"] = server
            if any(v in server for v in ["Apache/2.", "nginx/1.", "Microsoft-IIS/"]):
                self.add_finding(
                    title="Server Version Disclosure",
                    severity="LOW",
                    description=f"Server header reveals software version: {server}",
                    evidence=f"Server: {server}",
                    remediation="Remove or genericize the Server header. In Apache: ServerTokens Prod. In nginx: server_tokens off.",
                    url=resp.url
                )

        # X-Powered-By
        xpb = headers.get("X-Powered-By", "")
        if xpb:
            self.info["x_powered_by"] = xpb
            self.add_finding(
                title="Technology Disclosure via X-Powered-By",
                severity="LOW",
                description=f"X-Powered-By header reveals backend technology: {xpb}",
                evidence=f"X-Powered-By: {xpb}",
                remediation="Remove X-Powered-By header. In PHP: expose_php = Off. In Express: app.disable('x-powered-by')",
                url=resp.url
            )

        # X-Generator
        xgen = headers.get("X-Generator", "")
        if xgen:
            self.add_finding(
                title="CMS/Generator Disclosure",
                severity="INFO",
                description=f"X-Generator header reveals CMS: {xgen}",
                evidence=f"X-Generator: {xgen}",
                remediation="Remove X-Generator header from CMS configuration.",
                url=resp.url
            )

    def _detect_tech(self, resp):
        """Detect technologies from response content and headers."""
        content = resp.text
        headers_str = str(resp.headers)
        detected = []

        for tech, sigs in self.TECH_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in content.lower() or sig.lower() in headers_str.lower():
                    detected.append(tech)
                    break

        self.info["technologies"] = list(set(detected))
        if detected:
            self.log(f"Detected: {', '.join(set(detected))}", "i")

        # WordPress specific
        if "WordPress" in detected:
            self._check_wordpress(resp)

    def _check_wordpress(self, resp):
        """WordPress specific checks."""
        # Check version
        match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', resp.text)
        if match:
            version = match.group(1)
            self.add_finding(
                title=f"WordPress Version Disclosure ({version})",
                severity="MEDIUM",
                description=f"WordPress version {version} found in generator meta tag. Outdated versions may have known CVEs.",
                evidence=f'<meta name="generator" content="WordPress {version}">',
                remediation="Remove generator meta tag. Add: remove_action('wp_head', 'wp_generator'); to functions.php",
                url=resp.url
            )

        # Check common sensitive paths
        wp_paths = ["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-json/wp/v2/users"]
        for path in wp_paths:
            r = self.get(path)
            if r and r.status_code in [200, 301, 302]:
                if path == "/xmlrpc.php":
                    self.add_finding(
                        title="WordPress XML-RPC Enabled",
                        severity="MEDIUM",
                        description="xmlrpc.php is accessible. Can be abused for brute-force, DDoS amplification.",
                        evidence=f"GET {self.url}{path} → {r.status_code}",
                        remediation="Disable XML-RPC if not needed. Add to .htaccess: <Files xmlrpc.php> deny from all </Files>",
                        url=self.url + path
                    )
                elif path == "/wp-json/wp/v2/users":
                    self.add_finding(
                        title="WordPress User Enumeration via REST API",
                        severity="MEDIUM",
                        description="WordPress REST API exposes user list without authentication.",
                        evidence=f"GET {self.url}{path} → {r.status_code}\n{r.text[:300]}",
                        remediation="Add filter to hide users: add_filter('rest_endpoints', function($endpoints){unset($endpoints['/wp/v2/users']); return $endpoints;});",
                        url=self.url + path
                    )

    def _check_ssl(self):
        """Check SSL/TLS configuration."""
        if self.parsed.scheme != "https":
            self.add_finding(
                title="No HTTPS — Unencrypted Communication",
                severity="HIGH",
                description="The application is served over HTTP without encryption. Credentials and session tokens are transmitted in plaintext.",
                evidence=f"URL scheme: {self.parsed.scheme}",
                remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS. Use HSTS.",
                url=self.url
            )
            return

        host = self.parsed.hostname
        port = self.parsed.port or 443

        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.create_connection((host, port), timeout=5), server_hostname=host)
            cert = conn.getpeercert()
            conn.close()

            # Check expiry
            import datetime as dt
            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_date = dt.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - dt.datetime.utcnow()).days
                self.info["ssl_expires"] = expire_str
                self.info["ssl_days_left"] = days_left
                if days_left < 30:
                    self.add_finding(
                        title=f"SSL Certificate Expiring Soon ({days_left} days)",
                        severity="HIGH" if days_left < 7 else "MEDIUM",
                        description=f"SSL certificate expires in {days_left} days on {expire_str}.",
                        evidence=f"Certificate expiry: {expire_str}",
                        remediation="Renew the SSL certificate immediately.",
                        url=self.url
                    )

            # Check TLS version
            ssl_version = conn.version() if hasattr(conn, 'version') else "Unknown"
            self.info["tls_version"] = ssl_version

        except ssl.SSLError as e:
            self.add_finding(
                title="SSL Certificate Error",
                severity="HIGH",
                description=f"SSL certificate validation failed: {e}",
                evidence=str(e),
                remediation="Install a valid SSL certificate from a trusted CA.",
                url=self.url
            )
        except Exception as e:
            self.info["ssl_error"] = str(e)

    def _check_dns(self):
        """DNS reconnaissance."""
        host = self.parsed.hostname
        try:
            ip = socket.gethostbyname(host)
            self.info["ip_address"] = ip
            self.log(f"Resolved {host} → {ip}", "i")

            # Check for internal IP (SSRF indicator)
            if ip.startswith(("10.", "192.168.", "172.16.", "127.")):
                self.add_finding(
                    title="Internal IP Address Exposed",
                    severity="INFO",
                    description=f"Target resolves to internal/private IP: {ip}",
                    evidence=f"{host} → {ip}",
                    remediation="Ensure internal systems are not directly exposed. Use proper network segmentation.",
                    url=self.url
                )
        except Exception as e:
            self.info["dns_error"] = str(e)

    def _check_robots(self):
        """Check robots.txt for sensitive paths."""
        resp = self.get("/robots.txt")
        if resp and resp.status_code == 200 and "text/plain" in resp.headers.get("Content-Type", ""):
            self.info["robots_txt"] = resp.text[:2000]
            disallowed = re.findall(r"Disallow:\s*(.+)", resp.text)
            self.log(f"robots.txt found — {len(disallowed)} Disallow entries", "i")

            sensitive_patterns = [
                "admin", "login", "backup", "config", "database",
                "secret", "private", "api", "internal", ".env"
            ]
            interesting = [p for p in disallowed if any(s in p.lower() for s in sensitive_patterns)]
            if interesting:
                self.add_finding(
                    title="Sensitive Paths in robots.txt",
                    severity="INFO",
                    description="robots.txt reveals sensitive paths that should not be publicly disclosed.",
                    evidence="Disallow entries:\n" + "\n".join(interesting),
                    remediation="Do not rely on robots.txt for security. Protect sensitive paths with proper authentication.",
                    url=self.url + "/robots.txt"
                )

    def _check_sitemap(self):
        """Check sitemap for endpoint discovery."""
        for path in ["/sitemap.xml", "/sitemap_index.xml"]:
            resp = self.get(path)
            if resp and resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
                urls = re.findall(r"<loc>(.*?)</loc>", resp.text)
                self.info["sitemap_urls"] = urls[:50]
                self.log(f"Sitemap found — {len(urls)} URLs", "i")
                break

    def _check_security_txt(self):
        """Check for security.txt (good practice indicator)."""
        for path in ["/.well-known/security.txt", "/security.txt"]:
            resp = self.get(path)
            if resp and resp.status_code == 200:
                self.info["security_txt"] = resp.text[:500]
                self.log("security.txt found", "i")
                return

        self.add_finding(
            title="No security.txt Found",
            severity="INFO",
            description="security.txt is missing. This file helps researchers report vulnerabilities.",
            evidence="/.well-known/security.txt → 404",
            remediation="Create /.well-known/security.txt with contact and disclosure policy per RFC 9116.",
            url=self.url
        )

    def _check_common_files(self, resp):
        """Check for commonly exposed sensitive files."""
        sensitive_files = [
            ("/.env",              "Environment File",     "CRITICAL"),
            ("/.git/HEAD",         "Git Repository",       "HIGH"),
            ("/.git/config",       "Git Config",           "HIGH"),
            ("/config.php",        "PHP Config File",      "HIGH"),
            ("/wp-config.php.bak", "WordPress Config Backup", "CRITICAL"),
            ("/database.yml",      "Database Config",      "HIGH"),
            ("/config/database.yml","Database Config",     "HIGH"),
            ("/.htpasswd",         "htpasswd File",        "HIGH"),
            ("/backup.zip",        "Backup Archive",       "HIGH"),
            ("/backup.sql",        "Database Backup",      "CRITICAL"),
            ("/phpinfo.php",       "PHP Info Page",        "HIGH"),
            ("/info.php",          "PHP Info Page",        "HIGH"),
            ("/server-status",     "Apache Server Status", "MEDIUM"),
            ("/server-info",       "Apache Server Info",   "MEDIUM"),
            ("/.DS_Store",         "macOS DS_Store",       "LOW"),
            ("/Thumbs.db",         "Windows Thumbs.db",    "LOW"),
            ("/.svn/entries",      "SVN Repository",       "HIGH"),
            ("/.hg/hgrc",          "Mercurial Repository", "HIGH"),
            ("/crossdomain.xml",   "Flash Crossdomain",    "MEDIUM"),
            ("/clientaccesspolicy.xml", "Silverlight Policy", "MEDIUM"),
        ]

        self.log("Checking sensitive files...", "*")
        for path, name, severity in sensitive_files:
            r = self.get(path)
            if r and r.status_code == 200 and len(r.text) > 10:
                self.add_finding(
                    title=f"Sensitive File Exposed: {name}",
                    severity=severity,
                    description=f"Sensitive file {path} is publicly accessible and is publicly accessible — download and inspect for credentials, tokens, DB connection strings, and internal paths.",
                    evidence=f"GET {self.url}{path} → {r.status_code}\n{r.text[:200]}",
                    remediation=f"Restrict access to {path} via web server configuration. Remove the file if not needed.",
                    url=self.url + path
                )
