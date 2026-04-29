"""
core/scanner.py - Main scan orchestrator
"""

from datetime import datetime, timezone
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from core.config import ScanConfig, OWASP_CATEGORIES
from core.http_client import HttpClient
from core.crawler import Crawler
from core.finding import ScanResults, Finding
from core.base_module import BaseModule


class Scanner:
    """
    Orchestrates the full scan lifecycle:
    1. Login
    2. Crawl
    3. Run each selected module
    4. Collect and deduplicate findings
    """

    VERSION = "1.0.0"

    def __init__(self, config: ScanConfig, console: Console):
        self.config = config
        self.console = console
        self.http = HttpClient(config, console)
        self.results = ScanResults(
            target_url=config.base_url,
            start_time=datetime.now(timezone.utc).isoformat(),
            scanner_version=self.VERSION,
            modules_run=config.modules,
        )

    def run(self) -> ScanResults:
        """Full scan pipeline."""
        # --- 1. Authenticate ------------------------------------------------
        if not self.config.quiet:
            self.console.print("\n[bold]Phase 1/4:[/bold] [cyan]Authentication[/cyan]")

        logged_in = self.http.login()
        if not logged_in:
            self.console.print("[red]Authentication failed. Scanning as unauthenticated.[/red]")

        # --- 2. Crawl -------------------------------------------------------
        if not self.config.quiet:
            self.console.print("\n[bold]Phase 2/4:[/bold] [cyan]Crawling[/cyan]")

        crawler = Crawler(self.http, self.config, self.console)
        urls, forms = crawler.crawl()
        self.results.stats["crawled_pages"] = len(crawler.visited)
        self.results.stats["discovered_forms"] = len(forms)
        self.results.stats["parameterized_urls"] = len(urls)

        # --- 3. Run modules -------------------------------------------------
        if not self.config.quiet:
            self.console.print(f"\n[bold]Phase 3/4:[/bold] [cyan]Vulnerability Scanning[/cyan]")
            self.console.print(f"  Modules: {', '.join(self.config.modules)}\n")

        all_findings: List[Finding] = []

        module_instances = self._load_modules()

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
            disable=self.config.quiet,
        ) as progress:
            for mod in module_instances:
                task = progress.add_task(
                    f"Running {mod.MODULE_NAME} ({mod.OWASP_CATEGORY} {mod.OWASP_NAME})",
                    total=None
                )
                try:
                    findings = mod.run(urls, forms)
                    all_findings.extend(findings)
                    progress.update(task, description=
                        f"[green]✓[/green] {mod.MODULE_NAME} — {len(findings)} finding(s)"
                    )
                except Exception as e:
                    err = f"Module {mod.MODULE_NAME} crashed: {e}"
                    self.results.errors.append(err)
                    self.console.print(f"[red]{err}[/red]")
                    progress.update(task, description=f"[red]✗[/red] {mod.MODULE_NAME} — error")

        # --- 4. Finalise ----------------------------------------------------
        self.results.end_time = datetime.now(timezone.utc).isoformat()
        self.results.add_findings(all_findings)

        if not self.config.quiet:
            self.console.print(f"\n[bold]Phase 4/4:[/bold] [cyan]Results Summary[/cyan]")
            self._print_summary()

        return self.results

    def _load_modules(self) -> List[BaseModule]:
        """Dynamically load configured modules."""
        from modules.injection import InjectionModule
        from modules.access_control import AccessControlModule

        module_map = {
            "injection": InjectionModule,
            "access_control": AccessControlModule,
        }

        loaded = []
        for name in self.config.modules:
            cls = module_map.get(name)
            if cls:
                loaded.append(cls(self.http, self.config, self.console))
            else:
                self.console.print(f"[yellow]Unknown module: {name}[/yellow]")
        return loaded

    def _print_summary(self):
        summary = self.results.summary()
        total = sum(summary.values())

        table = Table(title="Scan Results Summary", border_style="blue")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        severity_styles = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "cyan",
            "Informational": "dim",
        }

        for sev, count in summary.items():
            style = severity_styles.get(sev, "white")
            table.add_row(f"[{style}]{sev}[/{style}]", str(count))

        table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")
        self.console.print(table)

        # OWASP breakdown
        owasp_counts = {}
        for f in self.results.findings:
            cat = f.get("owasp_category", "Unknown")
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

        if owasp_counts:
            owasp_table = Table(title="OWASP Top 10:2025 Coverage", border_style="magenta")
            owasp_table.add_column("Category")
            owasp_table.add_column("Name")
            owasp_table.add_column("Findings", justify="right")
            for cat, count in sorted(owasp_counts.items()):
                name = OWASP_CATEGORIES.get(cat, "")
                owasp_table.add_row(cat, name, str(count))
            self.console.print(owasp_table)