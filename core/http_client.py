"""
core/http_client.py - HTTP session manager with auth, proxy, DVWA login
"""

import time
import re
import requests
import urllib3
from typing import Optional, Dict, Tuple
from urllib.parse import urljoin

from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HttpClient:
    """
    Manages a persistent requests.Session with:
    - DVWA form-based login (handles CSRF token)
    - Basic / Bearer auth support
    - Proxy, custom headers, cookie injection
    - Rate limiting via configurable delay
    - Robust error handling
    """

    def __init__(self, config, console: Console):
        self.config = config
        self.console = console
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self.session.headers.update(config.get_headers())

        if config.get_proxies():
            self.session.proxies.update(config.get_proxies())

        if config.extra_cookies:
            self.session.cookies.update(config.extra_cookies)

        self._authenticated = False
        self._last_request_time = 0.0

    # ------------------------------------------------------------------ #
    #  Authentication                                                      #
    # ------------------------------------------------------------------ #

    def login(self) -> bool:
        """Authenticate against the target. Returns True on success."""
        if self.config.auth_type == "basic":
            self.session.auth = (self.config.username, self.config.password)
            self._authenticated = True
            return True

        if self.config.auth_type == "bearer":
            # Header already set in get_headers()
            self._authenticated = True
            return True

        # Form-based login (DVWA default)
        return self._dvwa_form_login()

    def _dvwa_form_login(self) -> bool:
        login_url = self.config.login_url or urljoin(self.config.base_url + "/", "login.php")

        try:
            # 1. GET the login page to grab CSRF token
            resp = self._raw_get(login_url)
            if resp is None:
                self.console.print(f"[red]Cannot reach login URL: {login_url}[/red]")
                return False

            user_token = self._extract_token(resp.text)

            # 2. POST credentials
            data = {
                "username": self.config.username,
                "password": self.config.password,
                "Login": "Login",
            }
            if user_token:
                data["user_token"] = user_token

            resp2 = self.session.post(
                login_url,
                data=data,
                allow_redirects=True,
                timeout=self.config.timeout,
            )

            # 3. Validate login success
            if self._is_login_successful(resp2):
                self._authenticated = True
                if self.config.verbose:
                    self.console.print(f"[green]✓ Logged in as {self.config.username}[/green]")
                self._set_dvwa_security_level()
                return True

            self.console.print(
                f"[red]Login failed for {self.config.username}. "
                "Check credentials or login URL.[/red]"
            )
            return False

        except requests.RequestException as e:
            self.console.print(f"[red]Login request error: {e}[/red]")
            return False

    def _extract_token(self, html: str) -> Optional[str]:
        """Extract DVWA's user_token CSRF field."""
        match = re.search(
            r'<input[^>]+name=["\']user_token["\'][^>]+value=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if match:
            return match.group(1)
        # Try reversed attribute order
        match = re.search(
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']user_token["\']',
            html, re.IGNORECASE
        )
        return match.group(1) if match else None

    def _is_login_successful(self, resp: requests.Response) -> bool:
        """Heuristics to detect successful DVWA login."""
        indicators_success = ["Welcome to Damn Vulnerable", "Logout", "DVWA Security", "index.php"]
        indicators_fail = ["Login failed", "incorrect", "username or password"]

        text_lower = resp.text.lower()
        for ind in indicators_fail:
            if ind.lower() in text_lower:
                return False
        for ind in indicators_success:
            if ind.lower() in text_lower:
                return True
        # Fallback: if redirected away from login page
        return "login.php" not in resp.url

    def _set_dvwa_security_level(self):
        """Set DVWA security level via /security.php."""
        security_url = urljoin(self.config.base_url + "/", "security.php")
        try:
            resp = self._raw_get(security_url)
            if resp is None:
                return
            token = self._extract_token(resp.text)
            data = {"security": self.config.security_level, "seclev_submit": "Submit"}
            if token:
                data["user_token"] = token
            self.session.post(security_url, data=data, timeout=self.config.timeout)
            if self.config.verbose:
                self.console.print(
                    f"[cyan]Security level set to: {self.config.security_level}[/cyan]"
                )
        except requests.RequestException:
            pass  # Non-fatal

    # ------------------------------------------------------------------ #
    #  Core request methods                                               #
    # ------------------------------------------------------------------ #

    def get(self, url: str, params: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        self._rate_limit()
        try:
            resp = self.session.get(
                url, params=params, timeout=self.config.timeout,
                allow_redirects=True, **kwargs
            )
            self._last_request_time = time.time()
            return resp
        except requests.RequestException as e:
            if self.config.verbose:
                self.console.print(f"[yellow]GET {url} error: {e}[/yellow]")
            return None

    def post(self, url: str, data: Optional[Dict] = None,
             json_body=None, **kwargs) -> Optional[requests.Response]:
        self._rate_limit()
        try:
            resp = self.session.post(
                url, data=data, json=json_body,
                timeout=self.config.timeout, allow_redirects=True, **kwargs
            )
            self._last_request_time = time.time()
            return resp
        except requests.RequestException as e:
            if self.config.verbose:
                self.console.print(f"[yellow]POST {url} error: {e}[/yellow]")
            return None

    def get_with_timing(self, url: str, params: Optional[Dict] = None,
                        **kwargs) -> Tuple[Optional[requests.Response], float]:
        """GET request that also returns elapsed time in seconds."""
        self._rate_limit()
        try:
            start = time.time()
            resp = self.session.get(
                url, params=params, timeout=max(self.config.timeout, 30),
                allow_redirects=True, **kwargs
            )
            elapsed = time.time() - start
            self._last_request_time = time.time()
            return resp, elapsed
        except requests.Timeout:
            elapsed = time.time() - start if 'start' in dir() else self.config.timeout
            return None, elapsed
        except requests.RequestException as e:
            if self.config.verbose:
                self.console.print(f"[yellow]GET (timed) {url} error: {e}[/yellow]")
            return None, 0.0

    def post_with_timing(self, url: str, data: Optional[Dict] = None,
                         **kwargs) -> Tuple[Optional[requests.Response], float]:
        """POST request with elapsed time measurement."""
        self._rate_limit()
        try:
            start = time.time()
            resp = self.session.post(
                url, data=data, timeout=max(self.config.timeout, 30),
                allow_redirects=True, **kwargs
            )
            elapsed = time.time() - start
            self._last_request_time = time.time()
            return resp, elapsed
        except requests.Timeout:
            elapsed = time.time() - start if 'start' in dir() else self.config.timeout
            return None, elapsed
        except requests.RequestException as e:
            if self.config.verbose:
                self.console.print(f"[yellow]POST (timed) {url} error: {e}[/yellow]")
            return None, 0.0

    def _raw_get(self, url: str) -> Optional[requests.Response]:
        """GET without rate limiting (used for login prep)."""
        try:
            return self.session.get(url, timeout=self.config.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def _rate_limit(self):
        if self.config.delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.config.delay:
                time.sleep(self.config.delay - elapsed)