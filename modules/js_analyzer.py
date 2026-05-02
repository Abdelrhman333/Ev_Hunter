"""
EVHunter — JavaScript Analyzer Module
Crawls pages, discovers JS files, and extracts:
  - API endpoints and routes
  - Hardcoded secrets / tokens
  - Internal hostnames and IPs
  - GraphQL queries and mutations
  - Cloud storage bucket URLs
  - Source map references
"""

import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin, urlparse

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

# ── Extraction patterns ───────────────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    r"""["'`](/api/[^"'`\s]{2,100})["'`]""",
    r"""["'`](https?://[^"'`\s]{5,150})["'`]""",
    r"""fetch\s*\(\s*["'`]([^"'`\s]+)["'`]""",
    r"""axios\.(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`\s]+)["'`]""",
    r"""\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]""",
    r"""["'`](/graphql[^"'`\s]*)["'`]""",
    r"""mutation\s+\w+|query\s+\w+\s*\{""",
    r"""["'`]((?:wss?|ws)://[^"'`\s]{5,100})["'`]""",   # WebSocket
]

S3_PATTERN       = re.compile(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]\.s3(?:[\.\-][^.\"'\s]+)?\.amazonaws\.com", re.I)
SOURCEMAP_PATTERN= re.compile(r"//# sourceMappingURL=(.+\.map)")
INTERNAL_IP      = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
LOCALHOST_PATTERN= re.compile(r"\b(localhost|127\.0\.0\.1):\d{2,5}\b")


class JSAnalyzerModule(ScannerModule):
    name        = "js"
    description = "JavaScript file crawling, endpoint extraction, and secret finding"

    def run(self, target: str, alive_hosts: list[dict] = None, **kwargs) -> dict[str, Any]:
        self._start_timer()
        self._status(f"JavaScript analysis on [cyan]{target}[/cyan]…")

        result: dict[str, Any] = {
            "ok":          True,
            "target":      target,
            "js_files":    [],
            "endpoints":   [],
            "secrets":     [],
            "s3_buckets":  [],
            "sourcemaps":  [],
            "internal_ips":[],
        }

        base_urls = []
        if alive_hosts:
            base_urls = [h["url"] for h in alive_hosts[:5]]
        else:
            u = target if target.startswith("http") else f"https://{target}"
            base_urls = [u]

        js_urls: set[str] = set()
        for base_url in base_urls:
            js_urls |= self._discover_js(base_url)

        result["js_files"] = list(js_urls)
        self._status(f"Found [cyan]{len(js_urls)}[/cyan] JS file(s) — extracting…")

        endpoints_set: set[str]   = set()
        s3_set: set[str]          = set()
        sourcemaps_set: set[str]  = set()
        ips_set: set[str]         = set()
        secrets: list[dict]       = []

        for js_url in list(js_urls)[:30]:  # cap
            content = self._fetch(js_url)
            if not content:
                continue

            # Endpoints
            for pattern in ENDPOINT_PATTERNS:
                for m in re.finditer(pattern, content):
                    ep = m.group(1) if m.lastindex else m.group(0)
                    if ep and len(ep) > 2:
                        endpoints_set.add(ep[:200])

            # S3 buckets
            s3_set |= set(S3_PATTERN.findall(content))

            # Source maps
            for sm in SOURCEMAP_PATTERN.findall(content):
                sourcemaps_set.add(urljoin(js_url, sm.strip()))

            # Internal IPs
            ips_set |= set(INTERNAL_IP.findall(content))
            if LOCALHOST_PATTERN.search(content):
                ips_set.add("localhost reference found")

            # Inline secrets (lightweight — full scan done by secret_scanner)
            for m in re.finditer(
                r"""(?i)(apiKey|api_key|token|secret|password|auth)\s*[=:]\s*["'`]([A-Za-z0-9_\-/+]{12,60})["'`]""",
                content
            ):
                val = m.group(2)
                if not any(fp in val.lower() for fp in ("example","placeholder","your","xxx","test")):
                    secrets.append({
                        "type":     m.group(1),
                        "value":    val[:40],
                        "url":      js_url,
                        "severity": "high",
                    })

        # Filter noise from endpoints
        result["endpoints"]    = self._filter_endpoints(list(endpoints_set))
        result["s3_buckets"]   = list(s3_set)[:20]
        result["sourcemaps"]   = list(sourcemaps_set)[:10]
        result["internal_ips"] = list(ips_set)[:20]
        result["secrets"]      = secrets[:30]

        self._ok(
            f"JS analysis done — {len(result['js_files'])} JS files, "
            f"{len(result['endpoints'])} endpoints, "
            f"{len(result['secrets'])} secret(s) [{self._elapsed()}]"
        )
        self._print_table(result)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _discover_js(self, url: str) -> set[str]:
        """Find all JS file URLs from an HTML page."""
        content = self._fetch(url, max_bytes=200_000)
        if not content:
            return set()

        js_urls: set[str] = set()
        # <script src="...">
        for m in re.finditer(r"""<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)['""]""", content, re.I):
            js_urls.add(urljoin(url, m.group(1)))

        # webpack chunk URLs in JS/HTML
        for m in re.finditer(r"""["'`]([^"'`]+\.chunk\.js)["'`]""", content):
            js_urls.add(urljoin(url, m.group(1)))

        return js_urls

    def _fetch(self, url: str, max_bytes: int = 500_000) -> str | None:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "EVHunter/2.0", "Accept": "*/*"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                ct = resp.headers.get("Content-Type", "")
                if any(x in ct for x in ("image", "video", "font")):
                    return None
                return resp.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _filter_endpoints(self, endpoints: list[str]) -> list[str]:
        """Remove noise like data URIs, font files, etc."""
        noise = ("data:", ".png", ".jpg", ".gif", ".svg", ".woff", ".ttf",
                 "google-analytics", "googletagmanager", "facebook.com/tr")
        return sorted(set(
            ep for ep in endpoints
            if not any(n in ep.lower() for n in noise)
        ))[:100]

    def _print_table(self, result: dict):
        if result["endpoints"]:
            tbl = Table(
                title=f"  [bold]JS Endpoints ({len(result['endpoints'])})[/bold]",
                box=box.SIMPLE, header_style="bold cyan",
            )
            tbl.add_column("Endpoint", style="white", max_width=80)
            for ep in result["endpoints"][:20]:
                tbl.add_row(ep[:80])
            console.print(tbl)

        if result["s3_buckets"]:
            console.print(f"  [yellow]  ⚠ S3 Buckets found: {', '.join(result['s3_buckets'][:5])}[/yellow]")

        if result["sourcemaps"]:
            console.print(f"  [yellow]  ⚠ Source maps found: {len(result['sourcemaps'])} (may expose original source)[/yellow]")
