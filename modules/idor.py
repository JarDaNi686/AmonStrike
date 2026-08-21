"""
AmonStrike — IDOR Module (Real-Target Edition)
Finds authorization failures in real applications.
Handles: numeric IDs, UUIDs, hashes, authenticated sessions.
"""
import re
import hashlib
from .base import BaseModule
from urllib.parse import urlparse, parse_qs, urljoin

ID_PATTERNS = [
    # Numeric
    (re.compile(r'/(\d+)(?:/|$|\?)'), "numeric"),
    (re.compile(r'[?&](id|uid|user_id|account_id|order_id|record_id|item_id|doc_id|pid|tid)=(\d+)', re.I), "numeric_param"),
    # UUID
    (re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'), "uuid"),
    # Hash-like
    (re.compile(r'/([0-9a-f]{32,64})(?:/|$|\?)'), "hash"),
]

ADMIN_ENDPOINTS = [
    "/api/admin", "/api/admin/users", "/api/v1/admin",
    "/api/users", "/api/v1/users", "/api/accounts",
    "/api/management", "/api/internal", "/api/staff",
    "/admin/api", "/admin/users", "/dashboard/api",
    "/api/reports", "/api/logs", "/api/audit",
    "/api/config", "/api/settings",
]


class IdorModule(BaseModule):
    NAME        = "idor"
    DESCRIPTION = "IDOR/BOLA — ID tampering, UUID, BFLA, response diffing"

    def run(self):
        self.log("Testing IDOR/BOLA...")

        # Find endpoints with IDs
        id_endpoints = self._find_id_endpoints()
        self.log(f"Found {len(id_endpoints)} ID-bearing endpoints", "i")

        for ep in id_endpoints[:20]:
            self._test_id_endpoint(ep)

        # BFLA test
        self._test_bfla()

        self.log(f"IDOR complete — {len(self.findings)} findings", "+")
        return self.result()

    def _find_id_endpoints(self) -> list:
        endpoints = []
        seen = set()

        r = self.get("")
        if not r:
            return endpoints

        # Extract all links
        all_links = re.findall(r'href=["\']([^"\'#]+)["\']', r.text)
        all_links += re.findall(r'"url"\s*:\s*"([^"]+)"', r.text)
        all_links += re.findall(r"'url'\s*:\s*'([^']+)'", r.text)

        # Add common API patterns
        all_links += [
            "/api/users/1", "/api/v1/users/1", "/api/orders/1",
            "/api/me", "/api/profile", "/api/account",
            "/api/user/1", "/api/v1/user/1",
        ]

        # Add recon endpoints
        all_links += list(getattr(self, "extra_endpoints", []))[:20]

        for link in all_links:
            abs_url = link if link.startswith("http") else urljoin(self.url, link)
            if self.parsed.netloc not in abs_url:
                continue
            if abs_url in seen:
                continue

            for pattern, id_type in ID_PATTERNS:
                m = pattern.search(abs_url)
                if m:
                    id_val = m.group(2) if id_type == "numeric_param" else m.group(1)
                    seen.add(abs_url)
                    endpoints.append({
                        "url":     abs_url,
                        "id":      id_val,
                        "id_type": id_type,
                        "pattern": pattern.pattern,
                    })
                    break

        return endpoints

    def _test_id_endpoint(self, ep: dict):
        url     = ep["url"]
        id_val  = ep["id"]
        id_type = ep["id_type"]

        # Get original response
        r_orig = self.session.get(url, timeout=self.timeout, verify=False,
                                  cookies=self.session.cookies)
        if not r_orig or r_orig.status_code not in [200,201]:
            return

        orig_hash   = hashlib.md5(r_orig.text.encode()).hexdigest()
        orig_len    = len(r_orig.text)

        if orig_len < 20:
            return  # Empty response, skip

        # Generate test IDs
        test_ids = self._generate_test_ids(id_val, id_type)

        for test_id in test_ids:
            # Build modified URL
            test_url = self._replace_id(url, id_val, test_id, id_type)
            if not test_url or test_url == url:
                continue

            r_test = self.session.get(test_url, timeout=self.timeout, verify=False)
            if not r_test or r_test.status_code not in [200,201]:
                continue

            test_hash = hashlib.md5(r_test.text.encode()).hexdigest()

            # Different content = different object accessed
            if test_hash == orig_hash:
                continue

            if len(r_test.text) < 20:
                continue

            # Check for sensitive data in response
            sensitive = self._detect_sensitive(r_test.text)
            sev = "CRITICAL" if sensitive else "HIGH"

            self.add_finding(
                title       = f"IDOR — Unauthorized Access via ID Manipulation: {urlparse(url).path}",
                severity    = sev,
                description = (
                    f"Changing the object ID from '{id_val}' to '{test_id}' "
                    f"returns different data belonging to another user/object. "
                    f"No authorization check is performed server-side."
                    + (f"\n\nSensitive data detected: {', '.join(sensitive)}" if sensitive else "")
                ),
                evidence    = (
                    f"Original URL: {url}\n"
                    f"Modified URL: {test_url}\n"
                    f"Original: {orig_len} bytes\n"
                    f"Modified: {len(r_test.text)} bytes (different content)\n"
                    f"Sensitive data: {sensitive}\n"
                    f"Response preview: {r_test.text[:300]}"
                ),
                remediation = (
                    "1. Verify object ownership server-side on every request\n"
                    "2. Never trust client-supplied IDs without authorization check\n"
                    "3. Use UUIDs instead of sequential integers\n"
                    "4. Implement object-level authorization middleware"
                ),
                url         = test_url,
                parameter   = "id",
                payload     = test_id,
                cve         = "CWE-639",
            )
            break

    def _generate_test_ids(self, orig_id: str, id_type: str) -> list:
        """Generate test IDs based on the type of original ID."""
        if id_type == "numeric":
            try:
                n = int(orig_id)
                # Try adjacent IDs + low IDs (admin usually has low IDs)
                tests = [n-1, n+1, n+2, 1, 2, 3, 100]
                return [str(t) for t in tests if t != n and t > 0]
            except ValueError:
                return []

        elif id_type == "numeric_param":
            try:
                n = int(orig_id)
                return [str(t) for t in [n-1, n+1, 1, 2, 3] if t != n and t > 0]
            except ValueError:
                return []

        elif id_type == "uuid":
            # Try replacing last segment with zeros or incrementing
            parts = orig_id.split("-")
            if len(parts) == 5:
                # Replace last part with 0s
                alt1 = "-".join(parts[:4] + ["000000000000"])
                # Replace with 1s
                alt2 = "-".join(parts[:4] + ["111111111111"])
                return [alt1, alt2] if alt1 != orig_id else [alt2]
            return []

        return []

    def _replace_id(self, url: str, old_id: str, new_id: str, id_type: str) -> str:
        """Safely replace ID in URL path only, not in hostname."""
        parsed = urlparse(url)
        new_path  = parsed.path.replace(old_id, new_id, 1)
        new_query = parsed.query.replace(f"={old_id}", f"={new_id}", 1) if id_type == "numeric_param" else parsed.query

        if new_path == parsed.path and new_query == parsed.query:
            return ""  # Nothing changed

        from urllib.parse import urlunparse
        return urlunparse((parsed.scheme, parsed.netloc, new_path,
                          parsed.params, new_query, parsed.fragment))

    def _detect_sensitive(self, text: str) -> list:
        found = []
        patterns = {
            "email":      r'[\w.+-]+@[\w-]+\.[\w.-]+',
            "phone":      r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "credit_card":r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            "ssn":        r'\b\d{3}-\d{2}-\d{4}\b',
            "password":   r'"password"\s*:\s*"[^"]+"',
            "token":      r'"(?:token|api_key|secret|access_token)"\s*:\s*"[^"]{10,}"',
            "address":    r'"(?:address|street|city|zip)"\s*:',
        }
        for data_type, pattern in patterns.items():
            if re.search(pattern, text, re.I):
                found.append(data_type)
        return found

    def _test_bfla(self):
        """Test admin endpoints as regular user."""
        for path in ADMIN_ENDPOINTS:
            r = self.get(path)
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
                if data and (isinstance(data, list) or
                            (isinstance(data, dict) and len(data) > 0)):
                    self.add_finding(
                        title       = f"BFLA — Admin Endpoint Accessible: {path}",
                        severity    = "CRITICAL",
                        description = (
                            f"Admin/privileged endpoint {path} is accessible without admin role. "
                            f"Returns data that should be restricted."
                        ),
                        evidence    = (
                            f"Path: {path}\nStatus: 200\n"
                            f"Response: {str(data)[:400]}"
                        ),
                        remediation = "Implement role-based access control on all admin endpoints.",
                        url         = self.url + path,
                        cve         = "CWE-285",
                    )
            except Exception:
                if len(r.text) > 100:
                    self.add_finding(
                        title       = f"BFLA — Admin Endpoint Accessible: {path}",
                        severity    = "HIGH",
                        description = f"Admin endpoint {path} returns 200 without admin privileges.",
                        evidence    = f"Path: {path}\nStatus: 200\nContent: {r.text[:200]}",
                        remediation = "Restrict admin endpoints to authorized roles only.",
                        url         = self.url + path,
                        cve         = "CWE-285",
                    )
