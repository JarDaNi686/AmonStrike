#!/usr/bin/env python3
"""
AmonStrike — GitHub OSINT Engine
Searches company GitHub repos for leaked secrets, internal endpoints,
API keys, hardcoded credentials, and architecture hints.
"""
import re, json, time, requests
from urllib.parse import urlparse

GITHUB_API = "https://api.github.com"

SECRET_PATTERNS = {
    "aws_key":      r'AKIA[0-9A-Z]{16}',
    "aws_secret":   r'[0-9a-zA-Z/+]{40}',
    "api_key":      r'(?:api[_-]?key|apikey)\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    "password":     r'(?:password|passwd|pwd)\s*=\s*["\']([^"\']{6,})["\']',
    "private_key":  r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "jwt_secret":   r'(?:jwt[_-]?secret|JWT_SECRET)\s*=\s*["\']([^"\']+)["\']',
    "db_url":       r'(?:mongodb|postgresql|mysql|redis)://[^\s"\'<>]+',
    "internal_url": r'https?://(?:internal|intra|staging|dev|corp)\.[^\s"\'<>]+',
    "slack_token":  r'xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}',
    "stripe":       r'sk_(?:live|test)_[A-Za-z0-9]{24,}',
    "firebase":     r'([a-z0-9\-]+)\.firebaseio\.com',
    "s3_bucket":    r's3\.amazonaws\.com/([a-z0-9\-\.]+)',
}

INTERESTING_FILES = [
    ".env", ".env.local", ".env.production", "config.yml", "config.json",
    "secrets.yml", "database.yml", "application.properties", "settings.py",
    "wp-config.php", "web.config", ".htpasswd", "docker-compose.yml",
    "Dockerfile", "terraform.tfvars", "*.pem", "*.key",
]


class GitHubOSINT:
    def __init__(self, token: str = ""):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "User-Agent": "AmonStrike/2.0",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def find_org(self, domain: str) -> list:
        """Find GitHub orgs matching a company domain."""
        company = domain.split(".")[0]
        orgs = []
        try:
            r = self.session.get(
                f"{GITHUB_API}/search/users",
                params={"q": f"{company} type:org", "per_page": 5},
                timeout=10,
            )
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    orgs.append(item["login"])
        except Exception:
            pass
        return orgs

    def search_secrets(self, org: str) -> list:
        """Search org repos for leaked secrets via GitHub code search."""
        findings = []
        queries = [
            f"org:{org} password",
            f"org:{org} api_key",
            f"org:{org} secret",
            f"org:{org} AKIA",
            f"org:{org} mongodb://",
            f"org:{org} .env",
        ]
        for q in queries:
            try:
                r = self.session.get(
                    f"{GITHUB_API}/search/code",
                    params={"q": q, "per_page": 10},
                    timeout=10,
                )
                if r.status_code == 200:
                    for item in r.json().get("items", []):
                        findings.append({
                            "type":    "github_code",
                            "repo":    item.get("repository", {}).get("full_name", ""),
                            "file":    item.get("path", ""),
                            "url":     item.get("html_url", ""),
                            "query":   q,
                        })
                time.sleep(2)  # GitHub rate limit
            except Exception:
                pass
        return findings

    def scan_repo_secrets(self, owner: str, repo: str) -> list:
        """Fetch file list and scan interesting files for secrets."""
        findings = []
        try:
            # Get recent commits to find interesting files
            r = self.session.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/HEAD",
                params={"recursive": "1"},
                timeout=15,
            )
            if r.status_code != 200:
                return findings

            tree = r.json().get("tree", [])
            interesting = [
                f for f in tree
                if any(pat.replace("*", "") in f.get("path","").lower()
                       for pat in INTERESTING_FILES)
                and f.get("type") == "blob"
            ]

            for f in interesting[:10]:
                content = self._fetch_file(owner, repo, f["path"])
                secrets = self._extract_secrets(content)
                for s in secrets:
                    findings.append({
                        "type":  "leaked_secret",
                        "repo":  f"{owner}/{repo}",
                        "file":  f["path"],
                        "secret_type": s["type"],
                        "value": s["value"][:40] + "...",
                        "severity": "CRITICAL",
                    })
        except Exception:
            pass
        return findings

    def _fetch_file(self, owner: str, repo: str, path: str) -> str:
        try:
            r = self.session.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
                timeout=10,
            )
            if r.status_code == 200:
                import base64
                content = r.json().get("content", "")
                return base64.b64decode(content).decode(errors="replace")
        except Exception:
            pass
        return ""

    def _extract_secrets(self, content: str) -> list:
        found = []
        for stype, pattern in SECRET_PATTERNS.items():
            for m in re.findall(pattern, content, re.I):
                val = m if isinstance(m, str) else (m[0] if m else "")
                if val and len(val) > 6:
                    found.append({"type": stype, "value": val})
        return found

    def full_scan(self, domain: str, gh_token: str = "") -> dict:
        if gh_token:
            self.session.headers["Authorization"] = f"Bearer {gh_token}"

        orgs     = self.find_org(domain)
        findings = []

        for org in orgs[:3]:
            findings.extend(self.search_secrets(org))
            # Get repos and scan top 5
            try:
                r = self.session.get(
                    f"{GITHUB_API}/orgs/{org}/repos",
                    params={"per_page": 5, "sort": "updated"},
                    timeout=10,
                )
                if r.status_code == 200:
                    for repo in r.json():
                        rname = repo.get("name","")
                        findings.extend(self.scan_repo_secrets(org, rname))
            except Exception:
                pass

        return {"orgs": orgs, "findings": findings}
