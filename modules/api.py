"""AmonStrike — API Security Testing Module"""
import json
import re
from .base import BaseModule

class ApiModule(BaseModule):
    NAME = "api"
    DESCRIPTION = "API endpoint discovery, authentication bypass, mass assignment"

    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/users", "/api/user", "/api/admin", "/api/auth",
        "/api/login", "/api/register", "/api/token", "/api/refresh",
        "/api/profile", "/api/settings", "/api/config",
        "/graphql", "/graphiql", "/api/graphql",
        "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/swagger-ui", "/swagger-ui.html",
        "/v1", "/v2", "/v3",
        "/rest", "/rest/api",
        "/api/health", "/api/status", "/api/ping",
        "/api/docs", "/api/documentation",
    ]

    def run(self):
        self.log("Discovering and testing API endpoints...")

        self._discover_endpoints()
        self._check_swagger()
        self._check_graphql()
        self._check_api_auth()
        self._check_http_methods()

        self.log(f"API scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _discover_endpoints(self):
        """Discover API endpoints."""
        found = []
        for path in self.API_PATHS:
            r = self.get(path)
            if r and r.status_code not in [404, 410]:
                found.append((path, r.status_code))
                ct = r.headers.get("Content-Type", "")
                if r.status_code == 200 and "json" in ct:
                    self.add_finding(
                        title=f"API Endpoint Found: {path}",
                        severity="INFO",
                        description=f"API endpoint {path} returns JSON data.",
                        evidence=f"GET {path} → {r.status_code}\nContent-Type: {ct}\nResponse: {r.text[:200]}",
                        remediation="Ensure all API endpoints require authentication. Implement proper authorization.",
                        url=self.url + path
                    )

                    # Check for unauthenticated data exposure
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            # Look for sensitive fields
                            data_str = json.dumps(data).lower()
                            sensitive = [f for f in ["password", "secret", "token", "key", "email", "ssn", "credit"]
                                        if f in data_str]
                            if sensitive:
                                self.add_finding(
                                    title=f"Sensitive Data Exposed via API: {path}",
                                    severity="HIGH",
                                    description=f"API endpoint {path} returns sensitive data without authentication: {', '.join(sensitive)}",
                                    evidence=f"GET {path} → {r.status_code}\nSensitive fields: {sensitive}\nSample: {r.text[:300]}",
                                    remediation="Require authentication on all API endpoints. Never return sensitive data unless explicitly needed. Implement field-level access control.",
                                    url=self.url + path,
                                    cve="CWE-359"
                                )
                        except Exception:
                            pass

        self.info["api_endpoints"] = found

    def _check_swagger(self):
        """Check for exposed Swagger/OpenAPI documentation."""
        swagger_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html"]
        for path in swagger_paths:
            r = self.get(path)
            if r and r.status_code == 200:
                self.add_finding(
                    title=f"API Documentation Exposed: {path}",
                    severity="MEDIUM",
                    description="API documentation is publicly accessible. This reveals all endpoints, parameters, and potentially authentication methods.",
                    evidence=f"GET {path} → {r.status_code}",
                    remediation="Restrict API documentation to authenticated users or internal networks only.",
                    url=self.url + path
                )

                # Extract endpoints from swagger
                try:
                    data = r.json()
                    paths = data.get("paths", {})
                    self.info["swagger_endpoints"] = list(paths.keys())[:20]
                    self.log(f"Swagger: {len(paths)} endpoints found", "i")
                except Exception:
                    pass
                break

    def _check_graphql(self):
        """Check for GraphQL introspection."""
        graphql_paths = ["/graphql", "/api/graphql", "/graphiql"]
        introspection_query = '{"query":"{ __schema { types { name } } }"}'

        for path in graphql_paths:
            r = self.post(path, data=introspection_query,
                         headers={"Content-Type": "application/json"})
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if "data" in data and "__schema" in str(data):
                        self.add_finding(
                            title="GraphQL Introspection Enabled",
                            severity="MEDIUM",
                            description="GraphQL introspection is enabled, exposing the complete schema including all types, queries, and mutations.",
                            evidence=f"POST {path}\nIntrospection query returned schema data.",
                            remediation="Disable GraphQL introspection in production. Implement query depth limiting and query complexity analysis.",
                            url=self.url + path
                        )
                except Exception:
                    pass

    def _check_api_auth(self):
        """Test API authentication bypass techniques."""
        api_paths = self.info.get("api_endpoints", [])
        for path, _ in api_paths[:5]:
            # Try without auth header
            for bypass in [
                {"X-Original-URL": "/admin"},
                {"X-Rewrite-URL": "/admin"},
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Remote-IP": "127.0.0.1"},
                {"X-Remote-Addr": "127.0.0.1"},
            ]:
                r = self.get(path, headers=bypass)
                if r and r.status_code == 200:
                    header_name = list(bypass.keys())[0]
                    self.add_finding(
                        title=f"API Authorization Bypass via {header_name}",
                        severity="CRITICAL",
                        description=f"API endpoint {path} can be accessed by adding {header_name} header.",
                        evidence=f"GET {path}\n{header_name}: {list(bypass.values())[0]}\n→ HTTP 200",
                        remediation="Never trust IP-based headers for authorization. Implement proper authentication and authorization middleware.",
                        url=self.url + path,
                        cve="CWE-863"
                    )
                    break

    def _check_http_methods(self):
        """Check for dangerous HTTP methods enabled."""
        methods_to_check = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "CONNECT"]
        r = self.session.options(self.url, timeout=self.timeout)
        if r:
            allow = r.headers.get("Allow", "")
            self.info["allowed_methods"] = allow

            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
            if dangerous:
                self.add_finding(
                    title=f"Dangerous HTTP Methods Enabled: {', '.join(dangerous)}",
                    severity="MEDIUM",
                    description=f"Server allows dangerous HTTP methods: {', '.join(dangerous)}. TRACE can enable XST attacks.",
                    evidence=f"OPTIONS {self.url}\nAllow: {allow}",
                    remediation="Disable unnecessary HTTP methods. Only allow GET, POST, and necessary REST methods.",
                    url=self.url
                )

            if "TRACE" in allow:
                self.add_finding(
                    title="HTTP TRACE Method Enabled — XST Attack",
                    severity="MEDIUM",
                    description="TRACE method is enabled. Cross-Site Tracing (XST) can steal cookies even with HttpOnly flag.",
                    evidence=f"OPTIONS → Allow: {allow}",
                    remediation="Disable HTTP TRACE method on all web servers.",
                    url=self.url,
                    cve="CVE-2003-1567"
                )
