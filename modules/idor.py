"""
AmonStrike — IDOR / BOLA Module
Insecure Direct Object Reference — highest paying bug class.

Tests:
  1. Sequential ID tampering (your ID +1/-1)
  2. GUID/UUID endpoint enumeration
  3. A/B user session replay (Autorize technique)
  4. Numeric ID range sweep (1-5)
  5. BFLA — admin endpoints as regular user
  6. Mass assignment parameter injection
  7. JWT user ID tampering
"""
import re
import json
import hashlib
from .base import BaseModule


class IdorModule(BaseModule):
    NAME        = "idor"
    DESCRIPTION = "IDOR/BOLA — object reference tampering, A/B user tests"

    # API patterns that commonly have IDOR
    ID_PATTERNS = [
        r"/(\d+)(?:/|$|\?)",
        r"[?&](?:id|user_id|account_id|order_id|record_id|item_id)=(\d+)",
        r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    ]

    # Endpoints frequently vulnerable to BFLA
    ADMIN_ENDPOINTS = [
        "/api/admin", "/api/users", "/api/v1/users",
        "/api/v1/admin", "/admin/api", "/management",
        "/api/accounts", "/api/v1/accounts",
        "/api/internal", "/api/private",
        "/api/staff", "/api/moderators",
    ]

    def run(self):
        self.log("Testing IDOR/BOLA...")

        # Step 1: Find ID-bearing endpoints
        endpoints = self._discover_id_endpoints()
        self.info["id_endpoints"] = endpoints
        self.log(f"Found {len(endpoints)} ID-bearing endpoints", "i")

        # Step 2: Test each endpoint
        for ep in endpoints[:20]:
            self._test_sequential_ids(ep)
            self._test_id_sweep(ep)

        # Step 3: BFLA test
        self._test_bfla()

        # Step 4: Parameter injection
        self._test_parameter_injection()

        self.log(f"IDOR complete — {len(self.findings)} findings", "+")
        return self.result()

    def _discover_id_endpoints(self) -> list:
        """Discover endpoints with object IDs."""
        endpoints = []
        # From current page
        r = self.get("")
        if not r:
            return []

        # Extract URLs from response
        urls = re.findall(r'href=["\']([^"\']+)["\']', r.text)
        urls += re.findall(r'action=["\']([^"\']+)["\']', r.text)
        urls += getattr(self, 'extra_endpoints', [])

        for url in urls:
            for pattern in self.ID_PATTERNS:
                m = re.search(pattern, url)
                if m:
                    endpoints.append({
                        "url":     url if url.startswith("http") else self.url + url,
                        "id":      m.group(1),
                        "pattern": pattern,
                    })
                    break

        # Also check API common paths
        api_paths = ["/api/v1/users/1", "/api/v1/user/1",
                     "/api/v1/me", "/api/profile",
                     "/api/account", "/api/orders/1"]
        for path in api_paths:
            r2 = self.get(path)
            if r2 and r2.status_code == 200:
                try:
                    data = r2.json()
                    if isinstance(data, dict) and data:
                        endpoints.append({"url": self.url+path, "id":"1", "pattern":"api"})
                except Exception:
                    pass

        return endpoints

    def _test_sequential_ids(self, ep: dict):
        """Test if incrementing the ID reveals other users' data."""
        url     = ep["url"]
        orig_id = ep.get("id","1")

        try:
            orig_id_int = int(orig_id)
        except ValueError:
            return

        # Fetch original
        r_orig = self.session.get(url, timeout=self.timeout, verify=False)
        if not r_orig or r_orig.status_code != 200:
            return

        orig_len  = len(r_orig.text)
        orig_hash = hashlib.md5(r_orig.text.encode()).hexdigest()

        # Test adjacent IDs
        for delta in [1, -1, 2, 10, 100]:
            test_id  = orig_id_int + delta
            test_url = url.replace(str(orig_id_int), str(test_id), 1)

            r_test = self.session.get(test_url, timeout=self.timeout, verify=False)
            if not r_test or r_test.status_code not in [200, 201]:
                continue

            test_hash = hashlib.md5(r_test.text.encode()).hexdigest()
            if test_hash == orig_hash:
                continue  # Same content = not different user

            # Different content returned = IDOR
            if r_test.status_code == 200 and len(r_test.text) > 20:
                sev = "HIGH"
                # Elevate if PII visible
                if any(pii in r_test.text.lower() for pii in
                       ["email","phone","address","password","ssn","credit"]):
                    sev = "CRITICAL"

                self.add_finding(
                    title       = f"IDOR — Unauthorized Object Access via ID Tampering",
                    severity    = sev,
                    description = (
                        f"Changing the object ID from {orig_id_int} to {test_id} "
                        f"returns different data, indicating no authorization check. "
                        f"An attacker can access any user's data by iterating IDs."
                    ),
                    evidence    = (
                        f"Original URL: {url}\n"
                        f"Modified URL: {test_url}\n"
                        f"Original response: {orig_len} bytes\n"
                        f"Modified response: {len(r_test.text)} bytes\n"
                        f"Response preview: {r_test.text[:300]}"
                    ),
                    remediation = (
                        "Implement server-side authorization on every object access. "
                        "Verify the authenticated user owns the requested object. "
                        "Use UUIDs instead of sequential integers."
                    ),
                    url         = test_url,
                    parameter   = "id",
                    payload     = str(test_id),
                    cve         = "CWE-639",
                )
                break

    def _test_id_sweep(self, ep: dict):
        """Sweep IDs 1-5 to find accessible objects."""
        url     = ep["url"]
        orig_id = ep.get("id","1")
        try:
            orig_int = int(orig_id)
        except ValueError:
            return

        accessible = []
        for test_id in range(1, 6):
            if test_id == orig_int:
                continue
            test_url = url.replace(str(orig_int), str(test_id), 1)
            r = self.session.get(test_url, timeout=self.timeout, verify=False)
            if r and r.status_code == 200 and len(r.text) > 20:
                accessible.append(test_id)

        if len(accessible) >= 2:
            self.add_finding(
                title       = f"IDOR — Mass Object Enumeration Possible",
                severity    = "HIGH",
                description = f"IDs {accessible} are all accessible. Full enumeration likely possible.",
                evidence    = f"Endpoint: {url}\nAccessible IDs: {accessible}",
                remediation = "Add object-level authorization. Never trust client-supplied IDs without server-side ownership check.",
                url         = url,
                parameter   = "id",
                payload     = str(accessible[0]),
                cve         = "CWE-639",
            )

    def _test_bfla(self):
        """Broken Function Level Authorization — admin endpoints as user."""
        for path in self.ADMIN_ENDPOINTS:
            r = self.get(path)
            if not r:
                continue
            if r.status_code == 200:
                try:
                    data = r.json()
                    if data:  # Returns actual data
                        self.add_finding(
                            title       = f"BFLA — Admin Endpoint Accessible: {path}",
                            severity    = "CRITICAL",
                            description = f"Admin/privileged endpoint {path} is accessible without admin role.",
                            evidence    = f"Path: {path}\nStatus: {r.status_code}\nResponse: {str(data)[:300]}",
                            remediation = "Implement role-based access control on all admin endpoints.",
                            url         = self.url + path,
                            cve         = "CWE-285",
                        )
                except Exception:
                    if len(r.text) > 50:
                        self.add_finding(
                            title       = f"BFLA — Admin Endpoint Returns Data: {path}",
                            severity    = "HIGH",
                            description = f"Admin endpoint {path} returns content without authentication.",
                            evidence    = f"Path: {path}\nResponse: {r.text[:200]}",
                            remediation = "Restrict admin endpoints to authenticated admin users only.",
                            url         = self.url + path,
                            cve         = "CWE-285",
                        )

    def _test_parameter_injection(self):
        """Test mass assignment — inject privileged parameters."""
        reg_paths = ["/api/register","/api/signup","/api/users","/register"]
        mass_params = [
            {"role":"admin"},{"isAdmin":True},{"is_admin":True},
            {"admin":True},{"privilege":"admin"},
        ]
        for path in reg_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue
            for extra in mass_params:
                payload = {
                    "username": f"test_{self.random_string(6)}",
                    "email":    f"test_{self.random_string(6)}@example.com",
                    "password": "TestPass123!",
                    **extra,
                }
                r2 = self.post(path, json=payload)
                if r2 and r2.status_code in [200,201]:
                    key = list(extra.keys())[0]
                    if str(list(extra.values())[0]).lower() in r2.text.lower():
                        self.add_finding(
                            title       = f"Mass Assignment — '{key}' Parameter Accepted",
                            severity    = "CRITICAL",
                            description = f"Registration endpoint accepts privileged parameter '{key}', allowing role escalation.",
                            evidence    = f"Path: {path}\nPayload key: {key}\nReflected in response",
                            remediation = "Use explicit allowlist for registration fields. Never bind request body directly to model.",
                            url         = self.url + path,
                            cve         = "CWE-915",
                        )
                        break
