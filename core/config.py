"""
core/config.py - Scan configuration and constants
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict

SCANNER_VERSION = "1.0.0"

OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational"]

# CVSS-inspired base scores per severity
SEVERITY_SCORES = {
    "Critical": 9.0,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 3.0,
    "Informational": 0.0,
}


@dataclass
class ScanConfig:
    # Target
    base_url: str
    login_url: Optional[str] = None

    # Auth
    username: str = "admin"
    password: str = "password"
    auth_type: str = "form"           # form | basic | bearer
    bearer_token: Optional[str] = None

    # DVWA
    security_level: str = "low"       # low | medium | high | impossible

    # Scan behavior
    deep_scan: bool = False
    modules: List[str] = field(default_factory=lambda: ["injection", "access_control"])
    timeout: int = 15
    delay: float = 0.3
    threads: int = 3
    max_urls: int = 200

    # Network
    proxy: Optional[str] = None
    user_agent: Optional[str] = None
    extra_cookies: Dict[str, str] = field(default_factory=dict)
    extra_headers: Dict[str, str] = field(default_factory=dict)
    verify_ssl: bool = False

    # Output
    output_dir: str = "./scan_output"
    output_formats: List[str] = field(default_factory=lambda: ["json", "md"])
    verbose: bool = False
    quiet: bool = False

    def get_proxies(self) -> Optional[Dict]:
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    def get_headers(self) -> Dict[str, str]:
        ua = self.user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        headers.update(self.extra_headers)
        if self.auth_type == "bearer" and self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers