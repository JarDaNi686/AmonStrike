"""AmonStrike — Directory/File Enumeration Module"""
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule

class DirModule(BaseModule):
    NAME = "dirs"
    DESCRIPTION = "Directory and file enumeration — hidden paths and admin panels"

    # Built-in wordlist
    DEFAULT_PATHS = [
        "admin", "administrator", "admin/", "admin/login", "admin/dashboard",
        "login", "signin", "register", "signup", "logout",
        "api", "api/v1", "api/v2", "api/v3", "api/users", "api/admin",
        "dashboard", "panel", "control", "manage", "management",
        "backup", "backups", "bak",
        "config", "configuration", "conf", "settings",
        "upload", "uploads", "files", "media", "static", "assets",
        "test", "tests", "testing", "dev", "development", "staging",
        "debug", "trace", "phpinfo.php",
        "wp-admin", "wp-login.php", "wp-content", "wp-includes",
        "phpmyadmin", "pma", "mysql", "database",
        "console", "shell", "cmd",
        "hidden", "private", "secret", "internal",
        "old", "backup.zip", "backup.tar.gz", "backup.sql",
        ".git", ".svn", ".hg", ".env", ".env.local", ".env.production",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "server-status", "server-info",
        "cgi-bin", "cgi",
        "error", "errors", "log", "logs",
        "tmp", "temp", "cache",
        "include", "includes", "lib", "library",
        "README.md", "README.txt", "CHANGELOG.md", "LICENSE",
        "composer.json", "package.json", "Gemfile",
        "web.config", ".htaccess", ".htpasswd",
        "graphql", "graphiql", "swagger", "swagger-ui", "swagger.json",
        "openapi.json", "openapi.yaml", "api-docs",
    ]

    INTERESTING_EXTENSIONS = [
        ".php", ".asp", ".aspx", ".jsp", ".py",
        ".bak", ".old", ".backup", ".orig", ".copy",
        ".sql", ".db", ".sqlite",
        ".log", ".txt", ".xml", ".json", ".yaml", ".yml",
        ".config", ".conf", ".ini",
        ".zip", ".tar", ".tar.gz", ".rar",
    ]

    def run(self):
        self.log("Starting directory/file enumeration...")

        # Use custom wordlist if provided
        paths = self.DEFAULT_PATHS[:]
        custom_wl = self.session_data.get("wordlist")
        if custom_wl and os.path.exists(custom_wl):
            with open(custom_wl) as f:
                paths = [line.strip() for line in f if line.strip()]
            self.log(f"Using custom wordlist: {len(paths)} paths", "i")

        found = []
        threads = self.session_data.get("threads", 10)

        def check_path(path):
            r = self.get(f"/{path}")
            if r and r.status_code in [200, 201, 301, 302, 403]:
                return (path, r.status_code, len(r.text))
            return None

        self.log(f"Checking {len(paths)} paths with {threads} threads...", "i")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_path, p): p for p in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, status, size = result
                    found.append(result)

                    severity = "INFO"
                    if any(s in path for s in ["admin", "config", "backup", "sql", ".env", "secret", "private"]):
                        severity = "HIGH"
                    elif status == 403:
                        severity = "LOW"
                    elif any(s in path for s in ["upload", "api", "dashboard"]):
                        severity = "MEDIUM"

                    self.add_finding(
                        title=f"{'Sensitive ' if severity in ['HIGH','CRITICAL'] else ''}Path Found: /{path}",
                        severity=severity,
                        description=f"Path /{path} is accessible (HTTP {status}). {'This path may expose sensitive data or functionality.' if severity == 'HIGH' else ''}",
                        evidence=f"GET /{path} → HTTP {status} ({size} bytes)",
                        remediation=f"Review if /{path} should be publicly accessible. Restrict with authentication or IP whitelist.",
                        url=f"{self.url}/{path}"
                    )

        self.info["paths_found"] = len(found)
        self.log(f"Enumeration complete — {len(found)} paths found", "+")
        return self.result()
