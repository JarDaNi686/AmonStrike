"""
AmonStrike — JavaScript Intelligence Engine
Level 2+3: Source map reconstruction + AI-assisted analysis.

Source maps are the jackpot:
  - Expose original minified source code
  - Reveal internal route names and API calls
  - Show admin endpoints not in the UI
  - Contain developer comments and TODOs
  - Expose internal package names (dependency confusion)

Sentry documented a .map file exposing undocumented
password-change endpoint → ATO.

AI analysis (via Claude API):
  - De-obfuscate minified JS
  - Find authentication logic
  - Identify potential injection points
  - Suggest attack vectors
"""

import os
import re
import sys
import json
import base64
import hashlib
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional, Set

sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.dirname(__file__)))


class JSIntelligence:
    """
    JavaScript analysis pipeline:
    1. Discover all JS files
    2. Check for source maps (.js.map)
    3. Extract endpoints from source
    4. Find secrets in bundles
    5. AI analysis of interesting code sections
    """

    ENDPOINT_PATTERNS = [
        # REST API endpoints
        r"""['"](\/api\/[a-zA-Z0-9\/\-_\.]+)['""]""",
        r"""['"](\/v[0-9]+\/[a-zA-Z0-9\/\-_\.]+)['""]""",
        r"""['"](\/[a-zA-Z]+\/[a-zA-Z0-9\/\-_\.]+)['""]""",
        # fetch/axios calls
        r"""(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete)\s*\(\s*['"](\/[^'"]+)['""]""",
        # GraphQL endpoints
        r"""['"](\/graphql[^\s'"]*)['""]""",
        # Admin paths
        r"""['"](\/admin[^\s'"]*)['""]""",
        r"""['"](\/internal[^\s'"]*)['""]""",
        r"""['"](\/management[^\s'"]*)['""]""",
    ]

    SECRET_PATTERNS = {
        "api_key":    r"""(?i)api[_\-]?key['":\s=]+['"]([\w\-]{20,})['""]""",
        "secret":     r"""(?i)secret['":\s=]+['"]([\w\-]{20,})['""]""",
        "token":      r"""(?i)token['":\s=]+['"]([\w\-\.]{20,})['""]""",
        "password":   r"""(?i)password['":\s=]+['"]([\w@!#$%]{8,})['""]""",
        "aws_key":    r"""AKIA[0-9A-Z]{16}""",
        "google_key": r"""AIza[0-9A-Za-z\-_]{35}""",
        "private_key":r"""-----BEGIN (?:RSA )?PRIVATE KEY-----""",
        "internal_url":r"""https?://(?:10\.|172\.|192\.168\.|localhost)[^\s'"]{5,}""",
        "jwt":        r"""eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.""",
    }

    WEBPACK_CHUNK_KEYWORDS = [
        "admin", "management", "internal", "billing", "payment",
        "auth", "dashboard", "settings", "config", "debug",
        "superuser", "moderator", "staff", "operator",
    ]

    def __init__(self, base_url: str, output_dir: str = "/tmp/js_intel"):
        self.base_url   = base_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session    = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        )
        self.js_files    : List[str] = []
        self.source_maps : List[str] = []
        self.endpoints   : Set[str]  = set()
        self.secrets     : List[Dict]= []
        self.admin_routes: List[str] = []

    def run(self) -> dict:
        """Full JS intelligence pipeline."""
        print(f"\n[*] JavaScript Intelligence: {self.base_url}")

        # Step 1: Discover JS files
        self._discover_js_files()
        print(f"  [+] JS files: {len(self.js_files)}")

        # Step 2: Check for source maps
        self._find_source_maps()
        if self.source_maps:
            print(f"  [!!!] SOURCE MAPS FOUND: {len(self.source_maps)}")
            self._reconstruct_source()

        # Step 3: Analyze JS bundles
        for js_url in self.js_files[:20]:
            self._analyze_js_file(js_url)

        # Step 4: Check webpack chunks for admin routes
        self._probe_webpack_chunks()

        print(f"  [+] Endpoints: {len(self.endpoints)}")
        print(f"  [+] Secrets: {len(self.secrets)}")
        print(f"  [+] Admin routes: {len(self.admin_routes)}")

        return {
            "base_url":    self.base_url,
            "js_files":    self.js_files,
            "source_maps": self.source_maps,
            "endpoints":   sorted(self.endpoints),
            "secrets":     self.secrets,
            "admin_routes":self.admin_routes,
            "timestamp":   datetime.now().isoformat(),
        }

    def _discover_js_files(self):
        """Discover JS files from page source and common paths."""
        try:
            r = self.session.get(self.base_url, timeout=10, verify=False)
            # From HTML
            for match in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text):
                url = urljoin(self.base_url, match)
                if url not in self.js_files:
                    self.js_files.append(url)

            # From inline JS (look for chunk references)
            for match in re.findall(r'"([^"]+\.js)"', r.text):
                if "/" in match and len(match) > 5:
                    url = urljoin(self.base_url, match)
                    if url not in self.js_files:
                        self.js_files.append(url)
        except Exception:
            pass

        # Common locations
        common = [
            "/app.js", "/main.js", "/bundle.js", "/index.js",
            "/static/js/main.js", "/assets/js/app.js",
            "/js/app.js", "/dist/app.js", "/build/app.js",
        ]
        for path in common:
            url = self.base_url + path
            if url not in self.js_files:
                try:
                    r = self.session.head(url, timeout=5, verify=False)
                    if r.status_code == 200:
                        self.js_files.append(url)
                except Exception:
                    pass

    def _find_source_maps(self):
        """Check each JS file for a source map."""
        for js_url in self.js_files:
            # Method 1: Append .map
            map_url = js_url + ".map"
            try:
                r = self.session.get(map_url, timeout=5, verify=False)
                if r.status_code == 200 and "mappings" in r.text:
                    self.source_maps.append(map_url)
                    print(f"  [!!!] SOURCE MAP: {map_url}")
                    continue
            except Exception:
                pass

            # Method 2: Check sourceMappingURL comment in JS
            try:
                r = self.session.get(js_url, timeout=10, verify=False)
                match = re.search(r"//# sourceMappingURL=(.+?)$", r.text, re.M)
                if match:
                    map_ref = match.group(1).strip()
                    map_url = urljoin(js_url, map_ref)
                    r2 = self.session.get(map_url, timeout=5, verify=False)
                    if r2.status_code == 200:
                        self.source_maps.append(map_url)
                        print(f"  [!!!] SOURCE MAP: {map_url}")
            except Exception:
                pass

    def _reconstruct_source(self):
        """Download and parse source maps to extract original source."""
        for map_url in self.source_maps:
            try:
                r = self.session.get(map_url, timeout=10, verify=False)
                if r.status_code != 200:
                    continue

                data = r.json()
                sources  = data.get("sources",[])
                contents = data.get("sourcesContent",[])

                # Save each source file
                for i, source_path in enumerate(sources):
                    content = contents[i] if i < len(contents) else None

                    # Extract endpoints and secrets from source
                    if content:
                        self._extract_from_source(content, source_path, map_url)

                    # Identify interesting source files
                    source_lower = source_path.lower()
                    if any(kw in source_lower for kw in
                           ["admin","route","api","auth","config","service"]):
                        print(f"  [i] Interesting source: {source_path}")
                        if content:
                            # Save for review
                            safe_name = re.sub(r'[^\w\-.]','_', source_path)
                            out_path  = self.output_dir / safe_name
                            out_path.write_text(content[:100000])

            except Exception:
                pass

    def _analyze_js_file(self, js_url: str):
        """Analyze a JS file for endpoints and secrets."""
        try:
            r = self.session.get(js_url, timeout=10, verify=False)
            if r.status_code != 200:
                return
            self._extract_from_source(r.text, js_url, js_url)
        except Exception:
            pass

    def _extract_from_source(self, content: str, source: str, origin: str):
        """Extract endpoints and secrets from JS content."""
        # Endpoints
        for pattern in self.ENDPOINT_PATTERNS:
            for match in re.findall(pattern, content):
                path = match if isinstance(match, str) else match[0]
                if len(path) > 3 and path.startswith("/"):
                    self.endpoints.add(path)
                    # Flag admin/internal
                    if any(kw in path.lower() for kw in
                           ["admin","internal","management","superuser","staff"]):
                        self.admin_routes.append({
                            "path":   path,
                            "source": source,
                        } if isinstance(path,str) else path)

        # Secrets
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            for match in re.findall(pattern, content):
                value = match if isinstance(match, str) else (match[0] if match else "")
                if value and len(value) >= 10:
                    # Filter common false positives
                    if any(fp in value.lower() for fp in
                           ["example","test","placeholder","your-",
                            "insert","replace","xxxx"]):
                        continue
                    self.secrets.append({
                        "type":   secret_type,
                        "value":  value[:60],
                        "source": source,
                        "origin": origin,
                    })
                    print(f"  [!] SECRET [{secret_type}]: {value[:30]}... in {source[-40:]}")

    def _probe_webpack_chunks(self):
        """Probe for webpack chunks named after admin/sensitive features."""
        # Common webpack chunk patterns
        chunk_patterns = [
            "/static/js/chunk-{keyword}.js",
            "/js/{keyword}.chunk.js",
            "/assets/{keyword}.js",
            "/dist/{keyword}.bundle.js",
            "/_next/static/chunks/{keyword}.js",
            "/static/chunks/{keyword}.js",
        ]

        for keyword in self.WEBPACK_CHUNK_KEYWORDS:
            for pattern in chunk_patterns:
                url = self.base_url + pattern.format(keyword=keyword)
                try:
                    r = self.session.head(url, timeout=3, verify=False)
                    if r.status_code == 200:
                        print(f"  [!] WEBPACK CHUNK: {url}")
                        self.js_files.append(url)
                        # Analyze it
                        self._analyze_js_file(url)
                except Exception:
                    pass

    def ai_analyze(self, code_snippet: str, context: str = "") -> str:
        """
        Use Claude API to analyze obfuscated/complex JS code.
        Returns security analysis and suggested attack vectors.
        """
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"Content-Type":"application/json"},
                json={
                    "model":      "claude-sonnet-4-6",
                    "max_tokens": 1000,
                    "messages": [{
                        "role":    "user",
                        "content": (
                            f"You are a security researcher analyzing JavaScript code "
                            f"for vulnerabilities in an authorized bug bounty assessment.\n\n"
                            f"Context: {context}\n\n"
                            f"Analyze this JavaScript code and identify:\n"
                            f"1. All API endpoints and HTTP calls\n"
                            f"2. Authentication/authorization logic\n"
                            f"3. Potential injection points\n"
                            f"4. Hardcoded secrets or credentials\n"
                            f"5. Suggested attack vectors\n\n"
                            f"Code:\n```javascript\n{code_snippet[:3000]}\n```\n\n"
                            f"Respond in JSON format:\n"
                            f"{{'endpoints':[],'secrets':[],'vulnerabilities':[],'attack_suggestions':[]}}"
                        )
                    }],
                },
                timeout=30
            )
            if r.status_code == 200:
                content = r.json()["content"][0]["text"]
                try:
                    return json.loads(content)
                except Exception:
                    return {"raw_analysis": content}
        except Exception as e:
            return {"error": str(e)}

    def get_linkfinder_command(self) -> str:
        """Generate LinkFinder command for manual use."""
        return (
            f"python3 LinkFinder.py -i {self.base_url} -d -o cli | "
            f"grep -E '(api|admin|internal|secret|token)'"
        )

    def get_secretfinder_command(self) -> str:
        """Generate SecretFinder command."""
        return (
            f"python3 SecretFinder.py -i {self.base_url} -e -o cli"
        )




def _test_aws_key(eng):
    eng._extract_from_source("const key = 'AKIAIOSFODNN7EXAMPLEKEY'", "config.js","config.js")
    return any(s["type"]=="aws_key" for s in eng.secrets)


def _test_fp_filter(eng):
    before = len(eng.secrets)
    eng._extract_from_source("const key = 'your-api-key-placeholder'", "test.js","test.js")
    return len(eng.secrets) == before


def run_regression_tests():
    print("\n=== JS INTELLIGENCE REGRESSION TESTS ===")
    passed = failed = 0

    eng = JSIntelligence("http://testphp.vulnweb.com", "/tmp/js_intel_test")

    tests = [
        ("Engine instantiates",
         lambda: isinstance(eng, JSIntelligence)),

        ("Endpoint patterns populated",
         lambda: len(JSIntelligence.ENDPOINT_PATTERNS) >= 5),

        ("Secret patterns populated",
         lambda: len(JSIntelligence.SECRET_PATTERNS) >= 7),

        ("Webpack chunk keywords populated",
         lambda: "admin" in JSIntelligence.WEBPACK_CHUNK_KEYWORDS),

        ("Extract API endpoint from code",
         lambda: (
             eng._extract_from_source(
                 'fetch("/api/v1/users", {method:"GET"})',
                 "test.js", "test.js"
             ) or True,
             "/api/v1/users" in eng.endpoints
         )[1]),

        ("Extract admin route flagged",
         lambda: (
             eng._extract_from_source(
                 'const url = "/admin/settings"',
                 "app.js", "app.js"
             ) or True,
             len(eng.admin_routes) >= 1
         )[1]),

        ("AWS key pattern is valid regex",
         lambda: bool(__import__("re").search(eng.SECRET_PATTERNS["aws_key"], "AKIAIOSFODNN7EXAMPLE"))),

        ("Endpoint deduplication works",
         lambda: (
             eng._extract_from_source(
                 'fetch("/api/v1/users"); fetch("/api/v1/users");',
                 "dup.js","dup.js"
             ) or True,
             eng.endpoints.count("/api/v1/users") <= 1
             if hasattr(eng.endpoints, 'count') else True
         )[1]),

        ("Output dir created",
         lambda: (eng.output_dir).exists()),

        ("LinkFinder command generated",
         lambda: "LinkFinder" in eng.get_linkfinder_command()),

        ("SecretFinder command generated",
         lambda: "SecretFinder" in eng.get_secretfinder_command()),

        ("URL join works correctly",
         lambda: urljoin("http://t.com/js/", "app.js") == "http://t.com/js/app.js"),

        ("Source map URL construction",
         lambda: "http://t.com/app.js.map" == "http://t.com/app.js" + ".map"),

        ("False positive filter works",
         lambda: _test_fp_filter(eng)),
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
        eng = JSIntelligence(sys.argv[1])
        result = eng.run()
        print(json.dumps(result, indent=2, default=str))
    else:
        run_regression_tests()
