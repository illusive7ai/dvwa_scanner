"""
core/crawler.py - Lightweight crawler to discover URLs, forms, and parameters
"""

import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn


@dataclass
class FormField:
    name: str
    field_type: str   # text, password, hidden, submit, select, textarea
    value: str = ""


@dataclass
class DiscoveredForm:
    action: str
    method: str               # GET | POST
    fields: List[FormField] = field(default_factory=list)
    found_on: str = ""


@dataclass
class DiscoveredUrl:
    url: str
    params: Dict[str, str] = field(default_factory=dict)
    found_on: str = ""


class Crawler:
    """
    Simple in-process crawler that:
    - Follows links within the same origin
    - Extracts all HTML forms with fields
    - Extracts URLs with GET parameters
    - Respects max_urls limit
    """

    # DVWA-specific pages known to contain vuln checks
    DVWA_KNOWN_PAGES = [
        "/vulnerabilities/sqli/",
        "/vulnerabilities/sqli_blind/",
        "/vulnerabilities/xss_r/",
        "/vulnerabilities/xss_s/",
        "/vulnerabilities/xss_d/",
        "/vulnerabilities/exec/",
        "/vulnerabilities/fi/",
        "/vulnerabilities/upload/",
        "/vulnerabilities/csrf/",
        "/vulnerabilities/brute/",
        "/vulnerabilities/idor/",
        "/vulnerabilities/weak_id/",
        "/vulnerabilities/captcha/",
        "/vulnerabilities/javascript/",
        "/vulnerabilities/open_redirect/",
        "/phpinfo.php",
        "/php.ini",
        "/setup.php",
    ]

    def __init__(self, http_client, config, console: Console):
        self.http = http_client
        self.config = config
        self.console = console
        self.visited: Set[str] = set()
        self.discovered_urls: List[DiscoveredUrl] = []
        self.discovered_forms: List[DiscoveredForm] = []
        self._base_parsed = urlparse(config.base_url)

    def crawl(self) -> Tuple[List[DiscoveredUrl], List[DiscoveredForm]]:
        """
        Start crawl from base_url. Returns (urls, forms).
        """
        if not self.config.quiet:
            self.console.print("[cyan]🕷  Starting crawler...[/cyan]")

        queue = [self.config.base_url]

        # Pre-seed with known DVWA paths
        for path in self.DVWA_KNOWN_PAGES:
            url = self.config.base_url + path
            if url not in queue:
                queue.append(url)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            disable=self.config.quiet,
        ) as progress:
            task = progress.add_task("[cyan]Crawling...", total=None)

            while queue and len(self.visited) < self.config.max_urls:
                url = queue.pop(0)
                norm = self._normalize(url)
                if norm in self.visited:
                    continue
                self.visited.add(norm)

                progress.update(task, description=f"[cyan]Crawling ({len(self.visited)}):[/cyan] {url[:80]}")

                resp = self.http.get(url)
                if resp is None or resp.status_code not in (200, 301, 302):
                    continue

                # Extract links and forms
                links = self._extract_links(resp.text, url)
                forms = self._extract_forms(resp.text, url)

                for link in links:
                    norm_link = self._normalize(link)
                    if norm_link not in self.visited and self._is_same_origin(link):
                        if link not in queue:
                            queue.append(link)
                        # Record as discovered URL with params
                        parsed = urlparse(link)
                        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        if params:
                            self.discovered_urls.append(
                                DiscoveredUrl(url=link, params=params, found_on=url)
                            )

                for form in forms:
                    self.discovered_forms.append(form)

        if not self.config.quiet:
            self.console.print(
                f"[green]✓ Crawl complete:[/green] "
                f"{len(self.visited)} pages, "
                f"{len(self.discovered_forms)} forms, "
                f"{len(self.discovered_urls)} parameterised URLs"
            )

        return self.discovered_urls, self.discovered_forms

    # ------------------------------------------------------------------ #
    #  HTML parsers                                                       #
    # ------------------------------------------------------------------ #

    def _extract_links(self, html: str, base: str) -> List[str]:
        links = []
        for match in re.finditer(r'href=["\']([^"\'#\s]+)["\']', html, re.IGNORECASE):
            href = match.group(1)
            full = urljoin(base, href)
            if self._is_same_origin(full):
                links.append(full)
        return links

    def _extract_forms(self, html: str, page_url: str) -> List[DiscoveredForm]:
        forms = []
        for form_match in re.finditer(
            r'<form([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL
        ):
            attrs = form_match.group(1)
            body = form_match.group(2)

            action = self._attr(attrs, "action") or page_url
            method = (self._attr(attrs, "method") or "GET").upper()
            action_url = urljoin(page_url, action)

            fields = []
            # input fields
            for inp in re.finditer(r'<input([^>]*)>', body, re.IGNORECASE):
                inp_attrs = inp.group(1)
                name = self._attr(inp_attrs, "name")
                if not name:
                    continue
                ftype = self._attr(inp_attrs, "type") or "text"
                value = self._attr(inp_attrs, "value") or ""
                fields.append(FormField(name=name, field_type=ftype.lower(), value=value))

            # textarea
            for ta in re.finditer(
                r'<textarea([^>]*)>(.*?)</textarea>', body, re.IGNORECASE | re.DOTALL
            ):
                ta_attrs = ta.group(1)
                name = self._attr(ta_attrs, "name")
                if name:
                    fields.append(FormField(name=name, field_type="textarea", value=ta.group(2).strip()))

            # select
            for sel in re.finditer(r'<select([^>]*)>', body, re.IGNORECASE):
                sel_attrs = sel.group(1)
                name = self._attr(sel_attrs, "name")
                if name:
                    # Try to get first option value
                    opt_match = re.search(r'<option[^>]+value=["\']([^"\']*)["\']', body)
                    value = opt_match.group(1) if opt_match else ""
                    fields.append(FormField(name=name, field_type="select", value=value))

            if fields:
                forms.append(DiscoveredForm(
                    action=action_url,
                    method=method,
                    fields=fields,
                    found_on=page_url,
                ))

        return forms

    # ------------------------------------------------------------------ #
    #  Helpers                                                            #
    # ------------------------------------------------------------------ #

    def _attr(self, attrs_str: str, attr_name: str) -> Optional[str]:
        match = re.search(
            rf'{attr_name}\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE
        )
        return match.group(1) if match else None

    def _normalize(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}"

    def _is_same_origin(self, url: str) -> bool:
        p = urlparse(url)
        return (
            p.netloc == self._base_parsed.netloc
            and p.scheme in ("http", "https")
            and not url.endswith((".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".ico", ".woff"))
        )