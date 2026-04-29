#!/usr/bin/env python3
"""
DVWA Vulnerability Scanner - Main CLI Entrypoint
Version: 1.0.0
Author: Security Research Tool
"""

import sys
import argparse
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.scanner import Scanner
from core.config import ScanConfig
from reports.report_generator import ReportGenerator

console = Console()

BANNER = """
██████╗ ██╗   ██╗██╗    ██╗ █████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║   ██║██║    ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ██║██║   ██║██║ █╗ ██║███████║    ███████╗██║     ███████║██╔██╗ ██║
██║  ██║╚██╗ ██╔╝██║███╗██║██╔══██║    ╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝ ╚████╔╝ ╚███╔███╔╝██║  ██║    ███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝   ╚═══╝   ╚══╝╚══╝ ╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
         DAST Web Vulnerability Scanner  |  OWASP Top 10:2025
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="DVWA DAST Vulnerability Scanner - OWASP Top 10:2025",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with login
  python main.py --url http://localhost/dvwa --username admin --password password

  # Deep scan with JSON + Markdown report
  python main.py --url http://localhost/dvwa --username admin --password password \\
    --level low --format json,md --output ./reports --deep

  # With proxy
  python main.py --url http://localhost/dvwa --proxy http://127.0.0.1:8080

  # Quick scan, specific modules only
  python main.py --url http://localhost/dvwa --modules injection,access_control
        """
    )

    # Target
    parser.add_argument("--url", required=True, help="Base URL of the target (e.g. http://localhost/dvwa)")
    parser.add_argument("--login-url", default=None, help="Login form URL (auto-detected if not provided)")

    # Auth
    parser.add_argument("--username", default="admin", help="Login username (default: admin)")
    parser.add_argument("--password", default="password", help="Login password (default: password)")
    parser.add_argument("--auth-type", choices=["form", "basic", "bearer"], default="form",
                        help="Authentication type (default: form)")
    parser.add_argument("--bearer-token", default=None, help="Bearer token (for --auth-type bearer)")

    # Scan config
    parser.add_argument("--level", choices=["low", "medium", "high", "impossible"], default="low",
                        help="DVWA security level to set/assume (default: low)")
    parser.add_argument("--deep", action="store_true", help="Enable deep scan (more payloads, slower)")
    parser.add_argument("--modules", default="all",
                        help="Comma-separated modules to run: injection,access_control,all (default: all)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--threads", type=int, default=3, help="Concurrent threads (default: 3)")
    parser.add_argument("--max-urls", type=int, default=200, help="Max URLs to crawl (default: 200)")

    # Network
    parser.add_argument("--proxy", default=None, help="HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", default=None, help="Custom User-Agent string")
    parser.add_argument("--cookies", default=None, help="Additional cookies as JSON string")
    parser.add_argument("--headers", default=None, help="Additional headers as JSON string")
    parser.add_argument("--verify-ssl", action="store_true", default=False, help="Verify SSL certificates")

    # Output
    parser.add_argument("--output", default="./scan_output", help="Output directory (default: ./scan_output)")
    parser.add_argument("--format", dest="output_format", default="json,md",
                        help="Report formats: json,md,pdf (default: json,md)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress, only show findings")

    return parser.parse_args()


def main():
    args = parse_args()

    if not args.quiet:
        console.print(Text(BANNER, style="bold cyan"))
        console.print(Panel(
            f"[bold]Target:[/bold] {args.url}\n"
            f"[bold]User:[/bold] {args.username}\n"
            f"[bold]Level:[/bold] {args.level}\n"
            f"[bold]Mode:[/bold] {'Deep' if args.deep else 'Standard'}\n"
            f"[bold]Modules:[/bold] {args.modules}",
            title="[bold yellow]Scan Configuration[/bold yellow]",
            border_style="yellow"
        ))

    # Parse extra cookies/headers
    extra_cookies = {}
    extra_headers = {}
    if args.cookies:
        try:
            extra_cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            console.print("[red]Error: --cookies must be valid JSON[/red]")
            sys.exit(1)
    if args.headers:
        try:
            extra_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            console.print("[red]Error: --headers must be valid JSON[/red]")
            sys.exit(1)

    # Resolve modules
    available_modules = ["injection", "access_control"]
    if args.modules == "all":
        modules_to_run = available_modules
    else:
        modules_to_run = [m.strip() for m in args.modules.split(",")]
        invalid = [m for m in modules_to_run if m not in available_modules]
        if invalid:
            console.print(f"[red]Unknown modules: {invalid}. Available: {available_modules}[/red]")
            sys.exit(1)

    # Build config
    config = ScanConfig(
        base_url=args.url.rstrip("/"),
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        auth_type=args.auth_type,
        bearer_token=args.bearer_token,
        security_level=args.level,
        deep_scan=args.deep,
        modules=modules_to_run,
        timeout=args.timeout,
        delay=args.delay,
        threads=args.threads,
        max_urls=args.max_urls,
        proxy=args.proxy,
        user_agent=args.user_agent,
        extra_cookies=extra_cookies,
        extra_headers=extra_headers,
        verify_ssl=args.verify_ssl,
        output_dir=args.output,
        output_formats=[f.strip() for f in args.output_format.split(",")],
        verbose=args.verbose,
        quiet=args.quiet,
    )

    # Create output directory
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)

    # Run scanner
    scanner = Scanner(config, console)
    results = scanner.run()

    # Generate reports
    generator = ReportGenerator(config, results, console)
    report_paths = generator.generate()

    if not args.quiet:
        console.print("\n")
        console.print(Panel(
            "\n".join([f"[green]✓[/green] {p}" for p in report_paths]),
            title="[bold green]Reports Generated[/bold green]",
            border_style="green"
        ))

    # Exit with non-zero if critical/high findings
    critical_high = sum(
        1 for f in results.findings
        if f.get("severity") in ("Critical", "High")
    )
    if critical_high > 0:
        console.print(f"\n[bold red]⚠  {critical_high} Critical/High severity finding(s) detected![/bold red]")
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()