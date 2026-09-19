#!/usr/bin/env python3
"""
AmonStrike — JavaScript Intelligence Engine
Reads client-side JS, finds hidden endpoints, API keys, secrets, tokens.
"""
import re, json, requests
from pathlib import Path
from urllib.parse import urljoin, urlparse

# Regex patterns for secrets and endpoints
PATTERNS = {
    "api_key":        r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    "secret":         r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
    "aws_key":        r'AKIA[0-9A-Z]{16}',
    "aws_secret":     r'(?:aws[_-]?secret|AWS_SECRET)[^"\']*["\']([A-Za-z0-9+/]{40})["\']',
    "jwt":            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    "bearer_token":   r'[Bb]earer\s+([A-Za-z0-9_\-\.]{20,})',
    "private_key":    r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "google_api":     r'AIza[0-9A-Za-z_\-]{35}',
    "slack_token":    r'xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}',
    "github_token":   r'ghp_[A-Za-z0-9]{36}',
    "stripe_key":     r'sk_(?:live|test)_[A-Za-z0-9]{24,}',
    "internal_url":   r'https?://(?:internal|intra|admin|corp|staging|dev|localhost|127\.0\.0\.1)[^\s"\'<>]+',
    "graphql":        r'(?:query|mutation|subscription)\s+\w+\s*\{',
    "endpoint":       r'["\'](?:/api/|/v[0-9]/|/rest/|/graphql)[^\s"\'<>]{3,}["\']',
    "s3_bucket":      r's3\.amazonaws\.com/([a-z0-9\-\.]+)',
    "firebase":       r'([a-z0-9\-]+)\.firebaseio\.com',
    "websocket":      r'wss?://[^\s"\'<>]+',
}

class JSAnalyzer:
    def __init__(self, base_url: str, session: requests.Session = None):
        self.base    = base_url
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0"
        self.visited = set()

    def find_js_files(self, html: str) -> list:
        """Extract all JS file URLs from HTML."""
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        return [urljoin(self.base, s) for s in srcs if s]

    def fetch_js(self, url: str) -> str:
        if url in self.visited:
            return ""
        self.visited.add(url)
        try:
            r = self.session.get(url, timeout=15, verify=False)
            if r.status_code == 200:
                return r.text
        except Exception:
            pass
        return ""

    def scan(self, html: str = "") -> dict:
        """Full JS analysis. Returns all findings."""
        results = {
            "endpoints":  [],
            "secrets":    [],
            "js_files":   [],
            "graphql":    False,
            "websockets": [],
        }

        # Fetch main page if no html
        if not html:
            try:
                r = self.session.get(self.base, timeout=15, verify=False)
                html = r.text
            except Exception:
                return results

        js_urls = self.find_js_files(html)
        results["js_files"] = js_urls

        # Scan inline JS + all JS files
        sources = [html] + [self.fetch_js(u) for u in js_urls[:20]]

        for src in sources:
            if not src:
                continue
            for pname, pattern in PATTERNS.items():
                matches = re.findall(pattern, src, re.I)
                for m in matches:
                    match = m if isinstance(m, str) else m[0] if m else ""
                    if not match:
                        continue
                    if pname == "endpoint":
                        clean = match.strip("\"'")
                        if clean not in results["endpoints"]:
                            results["endpoints"].append(clean)
                    elif pname == "websocket":
                        results["websockets"].append(match)
                    elif pname == "graphql":
                        results["graphql"] = True
                    elif pname in ("internal_url",):
                        results["endpoints"].append(match)
                    else:
                        entry = {"type": pname, "value": match[:80]}
                        if entry not in results["secrets"]:
                            results["secrets"].append(entry)

        results["endpoints"] = list(dict.fromkeys(results["endpoints"]))
        return results
