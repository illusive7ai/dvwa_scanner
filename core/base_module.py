"""
core/base_module.py - Abstract base class for all vulnerability scan modules
"""

from abc import ABC, abstractmethod
from typing import List

from rich.console import Console

from core.finding import Finding
from core.http_client import HttpClient
from core.config import ScanConfig
from core.crawler import DiscoveredUrl, DiscoveredForm


class BaseModule(ABC):
    """
    All vulnerability modules inherit from this class.
    Provides shared utilities and enforces a consistent interface.
    """

    # Subclasses must declare these
    MODULE_NAME: str = "base"
    OWASP_CATEGORY: str = "A00"
    OWASP_NAME: str = "Unknown"

    def __init__(self, http_client: HttpClient, config: ScanConfig, console: Console):
        self.http = http_client
        self.config = config
        self.console = console
        self.findings: List[Finding] = []

    @abstractmethod
    def run(
        self,
        urls: List[DiscoveredUrl],
        forms: List[DiscoveredForm],
    ) -> List[Finding]:
        """
        Execute all checks in this module.
        Returns a list of confirmed Finding objects.
        """
        ...

    # ------------------------------------------------------------------ #
    #  Shared helpers                                                     #
    # ------------------------------------------------------------------ #

    def log(self, msg: str):
        if not self.config.quiet:
            self.console.print(f"  [dim][{self.MODULE_NAME}][/dim] {msg}")

    def log_finding(self, finding: Finding):
        severity_colors = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "cyan",
            "Informational": "dim",
        }
        color = severity_colors.get(finding.severity, "white")
        if not self.config.quiet:
            self.console.print(
                f"  [bold green]⚡ FINDING:[/bold green] "
                f"[{color}][{finding.severity}][/{color}] "
                f"{finding.title} @ {finding.url}"
            )

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.log_finding(finding)

    def build_request_snippet(self, method: str, url: str, params: dict = None,
                               data: dict = None, headers: dict = None) -> str:
        """Format a human-readable request snippet for the report."""
        from urllib.parse import urlencode
        lines = [f"{method} {url}"]
        if params:
            lines[0] += "?" + urlencode(params)
        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        lines.append("")
        if data:
            lines.append(urlencode(data))
        return "\n".join(lines)

    def truncate_response(self, text: str, max_len: int = 500) -> str:
        """Trim response text for embedding in reports."""
        if text and len(text) > max_len:
            return text[:max_len] + f"\n... [truncated, total {len(text)} chars]"
        return text or ""

    def is_deep(self) -> bool:
        return self.config.deep_scan