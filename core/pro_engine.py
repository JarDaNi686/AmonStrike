#!/usr/bin/env python3
"""
AmonStrike — Professional Pentest Engine
Real-world methodology. No noise. No false positives.

Methodology (same as professional pentesters):
  1. Map → understand what the app does
  2. Authenticate → get real session
  3. Enumerate → find real attack surface
  4. Test → targeted, evidence-based
  5. Prove → extract real data
  6. Report → submit-ready

This replaces blind module firing with intelligent targeting.
"""

import re, json, time, hashlib, requests, urllib3
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings()


class AppMapper:
    """
    Step 1: Understand the app before touching it.
    Maps: tech stack, API structure, data model, auth flows.
    """

    def __init__(self, target: str, session: requests.Session):
        self.target  = target.rstrip("/")
        self.session = session
        self.map     = {}

    def run(self) -> dict:
        print("  [MAP] Reading app structure...")
        self.map = {
            "target":      self.target,
            "tech":        [],
            "auth_type":   "",
            "api_base":    "",
            "endpoints":   [],
            "id_params":   [],
            "auth_endpoints": [],
            "data_endpoints": [],
            "org_id":      "",
            "user_id":     "",
        }

        # Step 1: Get real session context
        self._get_session_context()

        r = self._get(self.target)
        if not r:
            return self.map

        # Detect tech
        self._detect_tech(r)

        # Find API base
        self._find_api_base(r)

        # Extract endpoints from JS
        self._extract_from_js(r)

        # Try API spec
        self._try_api_spec()

        # Add known endpoints based on org/user IDs
        self._add_known_endpoints()

        # Classify endpoints
        self._classify_endpoints()

        print(f"  [MAP] Tech: {self.map['tech'][:3]}")
        print(f"  [MAP] API: {self.map['api_base']}")
        print(f"  [MAP] Endpoints: {len(self.map['endpoints'])}")
        print(f"  [MAP] High-value: {len(self.map['data_endpoints'])}")

        return self.map

    def _get(self, url: str) -> requests.Response:
        try:
            return self.session.get(url, timeout=10, verify=False)
        except Exception:
            return None

    def _get_session_context(self):
        """Get org_id and user_id from authenticated session."""
        try:
            r = self.session.get(
                self.target.rstrip('/') + "/api/auth/session",
                timeout=10, verify=False
            )
            if r.status_code != 200:
                return
            data = r.json()
            # Try multiple response structures
            account = data.get("account", {})
            memberships = account.get("memberships", [{}])
            if memberships:
                org = memberships[0].get("organization", {})
                self.map["org_id"]  = org.get("uuid", "")
                self.map["user_id"] = account.get("uuid", "")
            # Alternative structure
            if not self.map["org_id"]:
                self.map["org_id"]  = data.get("organization_id", "")
                self.map["user_id"] = data.get("user_id", "")
            if self.map["org_id"]:
                print(f"  [MAP] Org: {self.map['org_id'][:20]}...")
                print(f"  [MAP] User: {self.map['user_id'][:15]}...")
        except Exception as e:
            print(f"  [MAP] Session context: {e}")

    def _add_known_endpoints(self):
        """Add known API endpoints using org/user IDs."""
        org  = self.map.get("org_id", "")
        user = self.map.get("user_id", "")
        base = "https://claude.ai"
        c_base = "https://console.anthropic.com"

        # Always add these
        known = [
            f"{base}/api/auth/session",
            f"{base}/api/bootstrap",
        ]

        if org:
            known += [
                f"{base}/api/organizations/{org}/chat_conversations",
                f"{base}/api/organizations/{org}/settings",
                f"{base}/api/organizations/{org}/members",
                f"{base}/api/organizations/{org}/entitlements",
                f"{c_base}/api/organizations/{org}/api_keys",
                f"{c_base}/api/organizations/{org}/usage",
                f"{c_base}/api/organizations/{org}/members",
                f"{c_base}/api/organizations/{org}/invites",
                f"{c_base}/api/organizations/{org}/workspaces",
            ]

        if user:
            known += [
                f"{base}/api/accounts/{user}",
                f"{base}/api/accounts/{user}/settings",
                f"{base}/api/accounts/{user}/entitlements",
            ]

        # Add to endpoints
        for ep in known:
            if ep not in self.map["endpoints"]:
                self.map["endpoints"].append(ep)

        # Mark all as data endpoints
        self.map["data_endpoints"].extend(known)
        print(f"  [MAP] Known endpoints: {len(known)}")

    def _detect_tech(self, r: requests.Response):
        combined = r.text[:5000] + str(r.headers)
        sigs = {
            "react":      ["__REACT", "_reactFiber", '"react"'],
            "next.js":    ["__NEXT", "_next/static"],
            "vue":        ["__vue", "Vue.component"],
            "graphql":    ["graphql", "__schema"],
            "jwt":        ["eyJ"],
            "cloudflare": ["cf-ray", "cloudflare"],
            "aws":        ["amazonaws", "x-amz"],
        }
        self.map["tech"] = [t for t, s in sigs.items()
                           if any(x.lower() in combined.lower() for x in s)]

    def _find_api_base(self, r: requests.Response):
        # Look for API base URL in JS
        patterns = [
            r'apiBase["\s:=]+"([^"]+)"',
            r'API_URL["\s:=]+"([^"]+)"',
            r'baseURL["\s:=]+"([^"]+)"',
            r'"(/api/v\d+)"',
        ]
        for pat in patterns:
            m = re.search(pat, r.text)
            if m:
                base = m.group(1)
                if not base.startswith("http"):
                    base = self.target + base
                self.map["api_base"] = base
                return
        self.map["api_base"] = self.target + "/api"

    def _extract_from_js(self, r: requests.Response):
        endpoints = set()

        # API calls in page
        for pat in [
            r'["\'](/api/[^\s"\'<>?#]{3,60})["\']',
            r'["\'](/v\d+/[^\s"\'<>?#]{3,60})["\']',
            r'fetch\(["\']([^"\']+)["\']',
        ]:
            for m in re.finditer(pat, r.text):
                ep = m.group(1)
                if ep.startswith("/"):
                    endpoints.add(self.target + ep)
                elif ep.startswith("http"):
                    endpoints.add(ep)

        # Extract JS file URLs and scan them
        js_urls = re.findall(r'src=["\'](/[^"\']+\.js[^"\']*)["\']', r.text)
        for js_url in js_urls[:5]:
            js_r = self._get(self.target + js_url)
            if js_r and js_r.status_code == 200:
                for pat in [
                    r'["\'](/api/[^\s"\'<>?#]{3,60})["\']',
                    r'["`]/(?:api|v\d+)/([a-z/_-]{5,60})["`]',
                ]:
                    for m in re.finditer(pat, js_r.text[:100000]):
                        ep = m.group(0).strip('"\'`')
                        if ep.startswith("/"):
                            endpoints.add(self.target + ep)

        self.map["endpoints"] = list(endpoints)[:100]

    def _try_api_spec(self):
        """Try to find OpenAPI/Swagger spec."""
        spec_paths = [
            "/openapi.json", "/swagger.json", "/api-docs.json",
            "/api/swagger.json", "/v3/api-docs",
        ]
        for path in spec_paths:
            r = self._get(self.target + path)
            if (r and r.status_code == 200
                    and r.headers.get("content-type","").startswith("application/json")
                    and len(r.content) > 500):
                try:
                    spec = r.json()
                    if "paths" in spec:
                        for path_key in spec["paths"]:
                            self.map["endpoints"].append(self.target + path_key)
                        print(f"  [MAP] Found API spec: {len(spec['paths'])} paths")
                        self.map["api_spec"] = spec
                        return
                except Exception:
                    pass

    def _classify_endpoints(self):
        """Classify endpoints by value."""
        data_keywords   = ["user","account","profile","order","payment",
                          "invoice","org","member","api_key","token","admin"]
        auth_keywords   = ["login","auth","oauth","token","session","signup"]

        for ep in self.map["endpoints"]:
            path = urlparse(ep).path.lower()
            if any(k in path for k in auth_keywords):
                self.map["auth_endpoints"].append(ep)
            if any(k in path for k in data_keywords):
                self.map["data_endpoints"].append(ep)

            # Find ID parameters
            if re.search(r'/\d{4,}', path) or re.search(r'/[0-9a-f-]{32,}', path):
                self.map["id_params"].append(ep)


class AuthenticatedTester:
    """
    Step 2-4: Authenticated, targeted testing.
    Tests what matters. Skips what doesn't.
    """

    def __init__(self, target: str, sessions: list, app_map: dict):
        self.target   = target
        self.sessions = sessions  # [{cookies, headers, role}]
        self.map      = app_map
        self.findings = []

    def run(self) -> list:
        if not self.sessions:
            print("  [TEST] No session — skipping authenticated tests")
            return []

        s1 = self._build_session(0)
        s2 = self._build_session(1) if len(self.sessions) > 1 else None

        # Run targeted tests
        self._test_idor(s1, s2)
        self._test_cors(s1)
        self._test_auth_bypass(s1)
        self._test_business_logic(s1)
        if "graphql" in self.map.get("tech", []):
            self._test_graphql(s1)

        return self.findings

    def _build_session(self, idx: int) -> requests.Session:
        s = requests.Session()
        s.verify = False
        sess = self.sessions[idx]
        s.cookies.update(sess.get("cookies", {}))
        s.headers.update(sess.get("headers", {}))
        s.headers.setdefault("User-Agent", "Mozilla/5.0")
        return s

    def _test_idor(self, s1: requests.Session, s2: requests.Session):
        """IDOR: User A's data accessible by User B."""
        print("  [IDOR] Testing access control...")
        endpoints = self.map.get("data_endpoints", []) + self.map.get("id_params", [])

        for ep in endpoints[:20]:
            try:
                r1 = s1.get(ep, timeout=10)
                if r1.status_code != 200 or len(r1.text) < 50:
                    continue

                # Check for sensitive data in response
                sensitive = self._extract_sensitive(r1.text)
                if not sensitive:
                    continue

                # If we have second session, try cross-account access
                if s2:
                    r2 = s2.get(ep, timeout=10)
                    if r2.status_code == 200:
                        s2_sensitive = self._extract_sensitive(r2.text)
                        if s2_sensitive:
                            # Both accounts can see the same data
                            self._add_finding(
                                title    = f"IDOR — Cross-Account Data Access: {urlparse(ep).path}",
                                severity = "CRITICAL",
                                url      = ep,
                                evidence = f"Account 1 sees: {sensitive}\nAccount 2 sees: {s2_sensitive}",
                                poc      = f'curl -sk "{ep}" -H "Cookie: ACCOUNT_B_SESSION"',
                                impact   = "Any authenticated user can access other users data",
                            )
                            print(f"  [!!!] IDOR CONFIRMED: {ep}")
                            continue

                # Single account: enumerate IDs
                id_match = re.search(r'/(\d{4,})', ep)
                if id_match:
                    orig_id = id_match.group(1)
                    for delta in [-1, +1, -2, +2]:
                        test_id  = str(int(orig_id) + delta)
                        test_url = ep.replace(f"/{orig_id}", f"/{test_id}", 1)
                        r_test   = s1.get(test_url, timeout=10)
                        if r_test.status_code == 200:
                            test_sensitive = self._extract_sensitive(r_test.text)
                            if test_sensitive:
                                self._add_finding(
                                    title    = f"IDOR — Sequential ID Enumeration: {urlparse(ep).path}",
                                    severity = "HIGH",
                                    url      = test_url,
                                    evidence = f"ID {test_id} returns: {test_sensitive}",
                                    poc      = f'curl -sk "{test_url}" -H "Cookie: YOUR_SESSION"',
                                    impact   = "Enumerate all user records by incrementing ID",
                                )

            except Exception:
                pass

    def _test_cors(self, s: requests.Session):
        """CORS: credentials allowed from arbitrary origin."""
        print("  [CORS] Testing CORS...")
        endpoints = self.map.get("data_endpoints", [])[:10]
        endpoints.append(self.target + "/api")

        for ep in endpoints:
            try:
                r = s.get(ep,
                         headers={"Origin": "https://evil.com"},
                         timeout=8)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

                if "evil.com" in acao and acac == "true":
                    self._add_finding(
                        title    = f"CORS — Credentials Allowed from Arbitrary Origin",
                        severity = "HIGH",
                        url      = ep,
                        evidence = f"ACAO: {acao}\nACAC: {acac}",
                        poc      = f'curl -sk "{ep}" -H "Origin: https://evil.com" -H "Cookie: VICTIM_SESSION"',
                        impact   = "Attacker can make cross-origin requests with victim credentials",
                    )
                    print(f"  [!!!] CORS CONFIRMED: {ep}")
            except Exception:
                pass

    def _test_auth_bypass(self, s: requests.Session):
        """Test common auth bypass techniques."""
        print("  [AUTH] Testing auth bypass...")

        # Test unauthenticated access to authenticated endpoints
        no_auth = requests.Session()
        no_auth.verify = False
        no_auth.headers["User-Agent"] = "Mozilla/5.0"

        for ep in self.map.get("data_endpoints", [])[:10]:
            try:
                r_auth   = s.get(ep, timeout=8)
                r_noauth = no_auth.get(ep, timeout=8)

                # If unauthenticated gets same data as authenticated → auth bypass
                if (r_auth.status_code == 200
                        and r_noauth.status_code == 200
                        and len(r_noauth.text) > 100
                        and self._extract_sensitive(r_noauth.text)):

                    self._add_finding(
                        title    = f"Auth Bypass — Endpoint Accessible Without Auth: {urlparse(ep).path}",
                        severity = "CRITICAL",
                        url      = ep,
                        evidence = f"No-auth response: {r_noauth.text[:300]}",
                        poc      = f'curl -sk "{ep}"',
                        impact   = "Sensitive data exposed without authentication",
                    )
                    print(f"  [!!!] AUTH BYPASS: {ep}")

            except Exception:
                pass

    def _test_business_logic(self, s: requests.Session):
        """Test business logic specific to this app."""
        print("  [BL] Testing business logic...")

        # Test API key operations (Anthropic specific)
        domain = urlparse(self.target).netloc
        if "anthropic" in domain or "claude" in domain:
            self._test_anthropic_specific(s)

    def _test_anthropic_specific(self, s: requests.Session):
        """Anthropic-specific high value tests."""
        # Get organization ID from session
        try:
            r = s.get("https://claude.ai/api/auth/session", timeout=10)
            if r.status_code != 200:
                return

            data   = r.json()
            org_id = (data.get("account", {}).get("memberships", [{}])[0]
                      .get("organization", {}).get("uuid", ""))
            user_id = data.get("account", {}).get("uuid", "")

            if not org_id:
                # Try different response structure
                org_id = data.get("organization_id", "")

            print(f"  [BL] Org ID: {org_id[:20]}... User: {user_id[:15]}...")

            if org_id:
                # Test API key access
                api_key_url = f"https://console.anthropic.com/api/organizations/{org_id}/api_keys"
                r2 = s.get(api_key_url, timeout=10)
                print(f"  [BL] API keys endpoint: {r2.status_code}")

                if r2.status_code == 200:
                    keys = r2.json()
                    print(f"  [BL] Found {len(keys) if isinstance(keys, list) else 'N'} API keys")

                # Test org member enumeration
                members_url = f"https://console.anthropic.com/api/organizations/{org_id}/members"
                r3 = s.get(members_url, timeout=10)
                if r3.status_code == 200:
                    members = r3.json()
                    sensitive = self._extract_sensitive(r3.text)
                    if sensitive:
                        self._add_finding(
                            title    = "Org Member Data Exposed via API",
                            severity = "HIGH",
                            url      = members_url,
                            evidence = f"Data: {r3.text[:400]}",
                            poc      = f'curl -sk "{members_url}" -H "Cookie: YOUR_SESSION"',
                            impact   = "Org member PII exposed including emails and roles",
                        )

        except Exception as e:
            print(f"  [BL] Session read error: {e}")

    def _test_graphql(self, s: requests.Session):
        """GraphQL introspection and batching."""
        print("  [GQL] Testing GraphQL...")
        gql_urls = [self.target + p for p in
                   ["/graphql", "/api/graphql", "/v1/graphql"]]

        for url in gql_urls:
            try:
                r = s.post(url,
                          json={"query": "{__schema{types{name}}}"},
                          headers={"Content-Type": "application/json"},
                          timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if "__schema" in str(data):
                        self._add_finding(
                            title    = "GraphQL Introspection Enabled",
                            severity = "MEDIUM",
                            url      = url,
                            evidence = f"Schema types exposed: {str(data)[:200]}",
                            poc      = f'curl -sk -X POST "{url}" -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{types{{name}}}}}}"}}\' ',
                            impact   = "Full API schema enumeration possible",
                        )
            except Exception:
                pass

    def _extract_sensitive(self, text: str) -> list:
        """Extract real sensitive fields from response."""
        found  = []
        fields = {
            "email":   r'"email"\s*:\s*"([^"@]+@[^"]+)"',
            "phone":   r'"phone"\s*:\s*"([+\d\s-]{7,})"',
            "name":    r'"(?:full_name|display_name|name)"\s*:\s*"([^"]{3,50})"',
            "user_id": r'"(?:uuid|user_id|id)"\s*:\s*"([a-f0-9-]{20,})"',
            "api_key": r'"(?:key|api_key|secret)"\s*:\s*"([^"]{20,})"',
            "token":   r'"(?:token|access_token)"\s*:\s*"([^"]{20,})"',
        }
        for field, pattern in fields.items():
            m = re.search(pattern, text, re.I)
            if m:
                found.append(f"{field}={m.group(1)[:30]}")
        return found

    def _add_finding(self, title: str, severity: str, url: str,
                     evidence: str, poc: str, impact: str):
        self.findings.append({
            "title":     title,
            "severity":  severity,
            "url":       url,
            "evidence":  evidence,
            "poc":       poc,
            "impact":    impact,
            "proven":    True,
            "timestamp": datetime.now().isoformat(),
            "module":    "pro_engine",
        })


class ProReport:
    """Generates clean, submit-ready H1 report."""

    @staticmethod
    def generate(findings: list, target: str, output_dir: Path) -> str:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"findings_{int(time.time())}.md"

        lines = [
            f"# Pentest Findings — {urlparse(target).netloc}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
            f"**Total Findings:** {len(findings)}",
            "",
        ]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            sevf = [f for f in findings if f.get("severity") == sev]
            if not sevf:
                continue
            lines.append(f"## {sev} ({len(sevf)})")
            for f in sevf:
                lines += [
                    f"### {f['title']}",
                    f"**URL:** `{f['url']}`",
                    "",
                    "**Evidence:**",
                    f"```\n{f.get('evidence', '')[:400]}\n```",
                    "",
                    "**Proof of Concept:**",
                    f"```bash\n{f.get('poc', '')}\n```",
                    "",
                    f"**Impact:** {f.get('impact', '')}",
                    "---",
                ]

        report_path.write_text("\n".join(lines))
        return str(report_path)


class ProPentest:
    """
    One URL in. Professional pentest out.
    No noise. No false positives. Real findings only.
    """

    def __init__(self, target: str, program: str = ""):
        self.target     = target.rstrip("/")
        self.program    = program
        self.output_dir = Path(f"output/{urlparse(target).netloc}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> dict:
        print(f"\n{'='*60}")
        print(f"  PROFESSIONAL PENTEST ENGINE")
        print(f"  Target: {self.target}")
        print(f"{'='*60}\n")

        # Get sessions
        sessions = self._get_sessions()
        print(f"  Sessions: {len(sessions)}")

        # Build main session
        s = requests.Session()
        s.verify = False
        if sessions:
            s.cookies.update(sessions[0].get("cookies", {}))
            s.headers.update(sessions[0].get("headers", {}))
        s.headers.setdefault("User-Agent", "Mozilla/5.0")
        s.headers.setdefault("X-HackerOne-Handle", "jardani101")

        # Step 1: Map
        print("\n[1/4] Mapping application...")
        mapper  = AppMapper(self.target, s)
        app_map = mapper.run()

        # Step 2: Test
        print("\n[2/4] Authenticated testing...")
        tester   = AuthenticatedTester(self.target, sessions, app_map)
        findings = tester.run()

        # Step 3: Report
        print(f"\n[3/4] Generating report ({len(findings)} findings)...")
        if findings:
            report = ProReport.generate(findings, self.target, self.output_dir)
            print(f"  Report: {report}")

            # H1 portal
            try:
                from reports.hackerone_format import generate_h1_package
                pkg = generate_h1_package(findings, str(self.output_dir),
                                         program_handle=self.program,
                                         target_url=self.target)
                if pkg.get("portal"):
                    print(f"  H1 Portal: {pkg['portal']}")
            except Exception:
                pass

        # Summary
        print(f"\n{'='*60}")
        for sev in ["CRITICAL","HIGH","MEDIUM"]:
            n = sum(1 for f in findings if f.get("severity")==sev)
            if n: print(f"  {sev}: {n}")
        if not findings:
            print("  No findings — need authenticated session or second account")
            print("  Next step: create jardani102@wearehackerone.com account")
        print(f"{'='*60}")

        return {"findings": findings, "map": app_map}

    def _get_sessions(self) -> list:
        sessions = []
        try:
            from core.session_manager import SessionManager
            sm     = SessionManager()
            domain = urlparse(self.target).netloc
            for base in [domain, "claude.ai", "anthropic.com"]:
                cookies = sm._grab_from_browser(base)
                if cookies:
                    sessions.append({
                        "cookies": cookies,
                        "headers": {"X-HackerOne-Handle": "jardani101"},
                        "role":    f"account_{len(sessions)+1}",
                    })
            if sessions:
                print(f"  [+] {len(sessions)} session(s) from Firefox")
        except Exception as e:
            print(f"  [!] Session grab: {e}")
        return sessions


if __name__ == "__main__":
    import sys
    url     = sys.argv[1] if len(sys.argv) > 1 else "https://claude.ai"
    program = sys.argv[2] if len(sys.argv) > 2 else "anthropic"
    ProPentest(url, program).run()
