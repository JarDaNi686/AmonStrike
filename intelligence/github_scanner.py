"""
AmonStrike — GitHub Intelligence & Credential Engine
Level 1: Find leaked secrets before the target notices.

TruffleHog found 28.65M secrets in 2025.
$15,000+ earned from GitHub leaks alone (Tillson Galloway).
$25,000 from force-pushed "deleted" commits (Sharon Brizinov).

What we scan:
  - GitHub code search (API + dorks)
  - Git history (all commits including deleted)
  - Force-pushed/deleted commits
  - Gists
  - Actions workflow logs
  - npm/pypi package metadata
  - LinkedIn → email format → breach lookup
"""

import re
import os
import sys
import json
import base64
import hashlib
import requests
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import quote

sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.dirname(__file__)))

# ── Secret Patterns ───────────────────────────────────────────

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": {
        "regex":    r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "verify":   "aws",
    },
    "AWS_SECRET_KEY": {
        "regex":    r"(?i)aws.{0,30}secret.{0,30}['\"]([A-Za-z0-9/+=]{40})['\"]",
        "severity": "CRITICAL",
        "verify":   "aws",
    },
    "GITHUB_TOKEN": {
        "regex":    r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "severity": "CRITICAL",
        "verify":   "github",
    },
    "GITHUB_OAUTH": {
        "regex":    r"[a-f0-9]{40}",  # Combined with context
        "context":  r"github.{0,30}[a-f0-9]{40}",
        "severity": "HIGH",
    },
    "GOOGLE_API_KEY": {
        "regex":    r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
        "verify":   "google",
    },
    "STRIPE_SECRET": {
        "regex":    r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
        "verify":   "stripe",
    },
    "STRIPE_PUBLISHABLE": {
        "regex":    r"pk_live_[0-9a-zA-Z]{24,}",
        "severity": "MEDIUM",
    },
    "SLACK_TOKEN": {
        "regex":    r"xox[baprs]-[0-9A-Za-z]{10,48}",
        "severity": "HIGH",
        "verify":   "slack",
    },
    "SLACK_WEBHOOK": {
        "regex":    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "severity": "HIGH",
    },
    "SENDGRID_KEY": {
        "regex":    r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "HIGH",
    },
    "TWILIO_SID": {
        "regex":    r"AC[a-f0-9]{32}",
        "severity": "HIGH",
    },
    "PRIVATE_KEY": {
        "regex":    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
    },
    "HEROKU_KEY": {
        "regex":    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "context":  r"heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}",
        "severity": "HIGH",
    },
    "DATABASE_URL": {
        "regex":    r"(?i)(mysql|postgres|postgresql|mongodb|redis)://[^'\"\s]{10,}",
        "severity": "CRITICAL",
    },
    "JWT_TOKEN": {
        "regex":    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
        "severity": "HIGH",
    },
    "GENERIC_SECRET": {
        "regex":    r"(?i)(secret|password|passwd|api_key|apikey|auth_token|access_token)"
                    r"['\"\s:=]+['\"]([A-Za-z0-9_\-]{20,})['\"]",
        "severity": "MEDIUM",
    },
    "NPM_TOKEN": {
        "regex":    r"npm_[A-Za-z0-9]{36}",
        "severity": "HIGH",
    },
    "DOCKER_HUB": {
        "regex":    r"(?i)docker.{0,20}password.{0,20}['\"]([^'\"]{8,})['\"]",
        "severity": "HIGH",
    },
    "FIREBASE_URL": {
        "regex":    r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
        "severity": "MEDIUM",
    },
    "AZURE_CLIENT": {
        "regex":    r"(?i)client.?secret.{0,20}['\"]([A-Za-z0-9~._\-]{34,})['\"]",
        "severity": "CRITICAL",
    },
    "INTERNAL_URL": {
        "regex":    r"https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|localhost|127\.)[^\s'\"]{5,}",
        "severity": "MEDIUM",
    },
}

# GitHub dorks for finding secrets
GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" secret_key',
    '"{domain}" api_key',
    '"{domain}" AWS_ACCESS_KEY_ID',
    'filename:.env "{domain}"',
    'filename:config.yml "{domain}" password',
    'filename:docker-compose.yml "{domain}"',
    'filename:.npmrc "{domain}" _authToken',
    'filename:settings.py "{domain}" SECRET_KEY',
    'filename:application.yml "{domain}" password',
    'filename:database.yml "{domain}"',
    'filename:wp-config.php "{domain}"',
    'org:{org} filename:.env',
    'org:{org} filename:config password',
    'org:{org} PRIVATE KEY',
    'org:{org} AWS_SECRET',
    'org:{org} filename:*.pem',
]


class GitHubScanner:
    """
    Scans GitHub for secrets leaked by the target organization.
    Uses GitHub Search API + pattern matching.
    """

    GITHUB_API = "https://api.github.com"
    GITHUB_RAW = "https://raw.githubusercontent.com"

    def __init__(self, domain: str, org: str = None,
                 github_token: str = None):
        self.domain  = domain
        self.org     = org or domain.split(".")[0]
        self.token   = github_token or os.environ.get("GITHUB_TOKEN","")
        self.session = requests.Session()
        if self.token:
            self.session.headers["Authorization"] = f"token {self.token}"
        self.session.headers["Accept"] = "application/vnd.github.v3+json"
        self.findings = []

    def scan(self) -> List[Dict]:
        """Run full GitHub secret scan."""
        print(f"\n[*] GitHub Secret Scanner: {self.domain}")

        # 1. Code search for secrets
        self._search_code()

        # 2. Org repositories scan
        if self.org:
            self._scan_org_repos()

        # 3. Gist scan
        self._scan_gists()

        print(f"  [+] GitHub scan complete: {len(self.findings)} secrets found")
        return self.findings

    def _search_code(self):
        """Search GitHub code for target-related secrets."""
        if not self.token:
            print("  [~] No GITHUB_TOKEN — code search limited")
            return

        for dork_template in GITHUB_DORKS[:8]:  # Limit API calls
            dork = dork_template.format(
                domain=self.domain, org=self.org
            )
            try:
                r = self.session.get(
                    f"{self.GITHUB_API}/search/code",
                    params={"q": dork, "per_page": 10},
                    timeout=15
                )
                if r.status_code == 200:
                    items = r.json().get("items",[])
                    for item in items:
                        self._analyze_file(item, dork)
                elif r.status_code == 403:
                    print("  [~] GitHub rate limit hit — waiting...")
                    import time; time.sleep(60)
                    break
            except Exception:
                pass

    def _analyze_file(self, item: dict, dork: str):
        """Download and analyze a file for secrets."""
        try:
            raw_url = item.get("html_url","").replace(
                "github.com","raw.githubusercontent.com"
            ).replace("/blob/","/")

            r = self.session.get(raw_url, timeout=10)
            if r.status_code != 200:
                return

            content = r.text
            repo    = item.get("repository",{}).get("full_name","")
            path    = item.get("path","")

            for secret_type, config in SECRET_PATTERNS.items():
                pattern = config.get("context","") or config["regex"]
                matches = re.findall(pattern, content)
                if matches:
                    for match in matches[:3]:
                        value = match if isinstance(match, str) else match[-1] if match else ""
                        if len(value) < 8:
                            continue

                        finding = {
                            "type":     secret_type,
                            "severity": config["severity"],
                            "value":    value[:50] + "..." if len(value)>50 else value,
                            "repo":     repo,
                            "file":     path,
                            "url":      item.get("html_url",""),
                            "dork":     dork,
                            "verified": False,
                        }

                        # Verify if possible
                        if config.get("verify"):
                            finding["verified"] = self._verify_secret(
                                secret_type, value, config["verify"]
                            )

                        self.findings.append(finding)
                        sev = config["severity"]
                        print(f"  [{'!!!' if sev=='CRITICAL' else '!'}] "
                              f"{secret_type} in {repo}/{path} "
                              f"({'LIVE' if finding['verified'] else 'unverified'})")

        except Exception:
            pass

    def _scan_org_repos(self):
        """Scan all public repos of the target org."""
        try:
            r = self.session.get(
                f"{self.GITHUB_API}/orgs/{self.org}/repos",
                params={"per_page": 30, "sort": "pushed"},
                timeout=15
            )
            if r.status_code != 200:
                return

            repos = r.json()
            print(f"  [i] Scanning {len(repos)} org repos...")

            for repo in repos[:10]:  # Limit
                repo_name = repo.get("full_name","")
                self._scan_repo_files(repo_name)

        except Exception:
            pass

    def _scan_repo_files(self, repo_full_name: str):
        """Scan specific files in a repo for secrets."""
        sensitive_files = [
            ".env", ".env.local", ".env.production",
            "config.yml","config.yaml","settings.py",
            "application.properties","docker-compose.yml",
        ]

        for filename in sensitive_files:
            try:
                r = self.session.get(
                    f"{self.GITHUB_API}/repos/{repo_full_name}/contents/{filename}",
                    timeout=10
                )
                if r.status_code == 200:
                    data    = r.json()
                    content = base64.b64decode(
                        data.get("content","")
                    ).decode("utf-8", errors="replace")

                    for secret_type, config in SECRET_PATTERNS.items():
                        matches = re.findall(config["regex"], content)
                        if matches:
                            self.findings.append({
                                "type":     secret_type,
                                "severity": config["severity"],
                                "value":    str(matches[0])[:50],
                                "repo":     repo_full_name,
                                "file":     filename,
                                "url":      data.get("html_url",""),
                                "verified": False,
                            })
                            print(f"  [!] {secret_type} in {repo_full_name}/{filename}")
            except Exception:
                pass

    def _scan_gists(self):
        """Scan GitHub gists for secrets."""
        if not self.token:
            return
        try:
            r = self.session.get(
                f"{self.GITHUB_API}/search/code",
                params={"q": f'"{self.domain}" gist', "per_page": 5},
                timeout=15
            )
            if r.status_code == 200:
                for item in r.json().get("items",[]):
                    self._analyze_file(item, "gist_scan")
        except Exception:
            pass

    def _verify_secret(self, secret_type: str, value: str, verify_type: str) -> bool:
        """Verify a secret is still live/valid."""
        try:
            if verify_type == "github":
                r = requests.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"token {value}"},
                    timeout=5
                )
                return r.status_code == 200

            elif verify_type == "slack":
                r = requests.post(
                    "https://slack.com/api/auth.test",
                    data={"token": value},
                    timeout=5
                )
                return r.json().get("ok",False)

            elif verify_type == "aws":
                # Don't actually verify AWS keys - too risky
                # Just check format validity
                return len(value) in [20, 40]

        except Exception:
            pass
        return False

    def get_trufflehog_command(self) -> str:
        """Generate TruffleHog command for deeper scanning."""
        return (
            f"trufflehog github --org={self.org} "
            f"--token=$GITHUB_TOKEN --only-verified "
            f"--json 2>/dev/null | jq ."
        )

    def get_gitleaks_command(self, repo_url: str = None) -> str:
        """Generate Gitleaks command."""
        target = repo_url or f"https://github.com/{self.org}"
        return (
            f"gitleaks detect --source {target} "
            f"--config gitleaks.toml --report-format json "
            f"--report-path gitleaks_report.json"
        )


class CredentialOSINT:
    """
    Credential intelligence: breach databases, email format, LinkedIn.
    """

    def __init__(self, domain: str):
        self.domain  = domain
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "AmonStrike/3.0"
        self.findings = []

    def full_osint(self) -> dict:
        """Run complete credential OSINT."""
        print(f"\n[*] Credential OSINT: {self.domain}")
        result = {
            "domain":          self.domain,
            "email_format":    None,
            "breach_count":    0,
            "breached_emails": [],
            "employees":       [],
        }

        # Email format
        fmt = self._discover_email_format()
        if fmt:
            result["email_format"] = fmt
            print(f"  [+] Email format: {fmt}")

        # HIBP domain check
        breaches = self._hibp_domain_check()
        result["breach_count"] = len(breaches)
        if breaches:
            print(f"  [!] Domain in {len(breaches)} breaches: "
                  f"{[b.get('Name','') for b in breaches[:3]]}")

        return result

    def _discover_email_format(self) -> Optional[str]:
        """Discover email format using Hunter.io."""
        hunter_key = os.environ.get("HUNTER_API","")
        if not hunter_key:
            # Fallback: check common patterns
            return self._guess_email_format()

        try:
            r = self.session.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": self.domain, "api_key": hunter_key},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json().get("data",{})
                return data.get("pattern","")
        except Exception:
            pass
        return None

    def _guess_email_format(self) -> str:
        """Guess common email formats."""
        # Most common: firstname.lastname, firstname, f.lastname
        return "first.last@" + self.domain

    def _hibp_domain_check(self) -> list:
        """Check if domain appears in HaveIBeenPwned breaches."""
        hibp_key = os.environ.get("HIBP_API","")
        if not hibp_key:
            return []
        try:
            r = self.session.get(
                f"https://haveibeenpwned.com/api/v3/breaches",
                headers={
                    "hibp-api-key": hibp_key,
                    "User-Agent":   "AmonStrike/3.0",
                },
                timeout=10
            )
            if r.status_code == 200:
                breaches = r.json()
                # Filter to those containing our domain
                return [b for b in breaches
                       if self.domain.split(".")[0].lower()
                       in b.get("Domain","").lower()]
        except Exception:
            pass
        return []

    def generate_email_wordlist(self, names: list) -> list:
        """
        Generate email permutations from employee names.
        Based on discovered email format.
        """
        emails = []
        for name in names:
            parts = name.lower().split()
            if len(parts) < 2:
                continue
            first, last = parts[0], parts[-1]
            f = first[0]

            candidates = [
                f"{first}.{last}@{self.domain}",
                f"{first}{last}@{self.domain}",
                f"{f}{last}@{self.domain}",
                f"{first}_{last}@{self.domain}",
                f"{first}@{self.domain}",
                f"{f}.{last}@{self.domain}",
                f"{last}.{first}@{self.domain}",
                f"{last}{f}@{self.domain}",
            ]
            emails.extend(candidates)
        return emails


def run_regression_tests():
    print("\n=== GITHUB INTELLIGENCE REGRESSION TESTS ===")
    passed = failed = 0

    scanner = GitHubScanner("testphp.vulnweb.com", "acunetix")
    osint   = CredentialOSINT("testphp.vulnweb.com")

    tests = [
        ("GitHubScanner instantiates",
         lambda: isinstance(scanner, GitHubScanner)),

        ("Org extracted from domain",
         lambda: scanner.org == "acunetix"),

        ("Secret patterns populated",
         lambda: len(SECRET_PATTERNS) >= 15),

        ("AWS key pattern valid",
         lambda: re.match(SECRET_PATTERNS["AWS_ACCESS_KEY"]["regex"],
                          "AKIAIOSFODNN7EXAMPLE") is not None),

        ("GitHub token pattern matches",
         lambda: re.match(SECRET_PATTERNS["GITHUB_TOKEN"]["regex"],
                          "ghp_" + "A"*36) is not None),

        ("Private key pattern matches",
         lambda: re.search(SECRET_PATTERNS["PRIVATE_KEY"]["regex"],
                           "-----BEGIN RSA PRIVATE KEY-----") is not None),

        ("Database URL pattern matches",
         lambda: re.search(SECRET_PATTERNS["DATABASE_URL"]["regex"],
                           "mysql://user:pass@host/db") is not None),

        ("JWT pattern matches",
         lambda: bool(re.search(SECRET_PATTERNS["JWT_TOKEN"]["regex"],
                          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"))),

        ("GitHub dorks have domain placeholder",
         lambda: any("{domain}" in d for d in GITHUB_DORKS)),

        ("GitHub dorks have org placeholder",
         lambda: any("{org}" in d for d in GITHUB_DORKS)),

        ("TruffleHog command generated",
         lambda: "trufflehog" in scanner.get_trufflehog_command()),

        ("Gitleaks command generated",
         lambda: "gitleaks" in scanner.get_gitleaks_command()),

        ("Verify returns bool",
         lambda: isinstance(scanner._verify_secret("JWT","test","unknown"), bool)),

        ("CredentialOSINT instantiates",
         lambda: isinstance(osint, CredentialOSINT)),

        ("Email guess returns string",
         lambda: "@" in osint._guess_email_format()),

        ("Email wordlist generates",
         lambda: len(osint.generate_email_wordlist(["John Smith", "Jane Doe"])) >= 8),

        ("Email wordlist contains domain",
         lambda: all("vulnweb.com" in e
                    for e in osint.generate_email_wordlist(["John Smith"]))),

        ("HIBP domain check no key → empty",
         lambda: osint._hibp_domain_check() == []),
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
    import sys
    if len(sys.argv) > 1:
        s = GitHubScanner(sys.argv[1])
        s.scan()
    else:
        run_regression_tests()
