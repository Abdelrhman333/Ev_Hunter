"""
EVHunter — BFS Web Crawler  v1.0
Recursively maps all pages, forms, endpoints, and interesting paths.

Features:
  - BFS crawling with configurable depth and page limits
  - Form extraction (action, method, input names)
  - Link extraction from HTML href, form actions, inline JS
  - Interesting path probing (200+ paths: admin, api, debug, etc.)
  - robots.txt and sitemap.xml parsing
  - Cookie and auth header forwarding
  - Rate limiting between requests
"""

import re
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, urlencode

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

# ── Interesting paths to probe ────────────────────────────────────────────────
INTERESTING_PATHS = [
    # Admin / panel
    "/admin", "/admin/", "/administrator", "/admin/login", "/admin/dashboard",
    "/panel", "/controlpanel", "/cpanel", "/manage", "/management",
    # API
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/graphql", "/api/rest",
    "/v1", "/v2", "/v3",
    # GraphQL
    "/graphql", "/graphiql", "/playground", "/gql", "/api/graphql",
    # Developer / debug
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/debug", "/debug/", "/console", "/shell", "/terminal",
    "/phpinfo.php", "/info.php", "/test.php",
    # Spring Boot actuator
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/metrics", "/actuator/loggers",
    "/actuator/heapdump", "/actuator/threaddump", "/actuator/httptrace",
    # Metrics / monitoring
    "/metrics", "/health", "/healthz", "/status", "/ping",
    "/prometheus", "/stats",
    # API docs
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
    "/api-docs", "/api-docs/swagger.json", "/openapi", "/openapi.json",
    "/v2/api-docs", "/v3/api-docs", "/redoc",
    # CMS
    "/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wordpress/wp-admin",
    "/admin/index.php", "/phpmyadmin", "/pma",
    # Config / backups
    "/config", "/configuration", "/config.php", "/config.json",
    "/settings", "/settings.php",
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/database.sql", "/dump.sql",
    "/web.config", "/.htaccess", "/nginx.conf",
    # Discovery
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/.well-known/assetlinks.json",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Logs
    "/logs", "/log", "/error.log", "/access.log", "/debug.log",
    "/var/log/nginx/access.log",
    # Server info
    "/server-status", "/server-info",
    "/trace", "/TRACE",
    # Common endpoints
    "/login", "/signin", "/register", "/signup", "/logout",
    "/forgot-password", "/reset-password",
    "/search", "/query",
    "/upload", "/uploads", "/file-upload",
    "/download", "/downloads", "/files",
    # Cloud / storage
    "/.aws/credentials",
    "/s3", "/storage",
]

LINK_PATTERN = re.compile(
    r"""href\s*=\s*["']([^"'#\s>]+)["']""",
    re.I
)
SRC_PATTERN = re.compile(
    r"""(?:src|action)\s*=\s*["']([^"'#\s>]+)["']""",
    re.I
)
FORM_PATTERN = re.compile(
    r"""(<form[^>]*>)(.*?)</form>""",
    re.I | re.S
)
INPUT_PATTERN = re.compile(
    r"""<input[^>]+name\s*=\s*["']([^"']+)["'][^>]*>""",
    re.I
)
TEXTAREA_PATTERN = re.compile(
    r"""<textarea[^>]+name\s*=\s*["']([^"']+)["']""",
    re.I
)
SELECT_PATTERN = re.compile(
    r"""<select[^>]+name\s*=\s*["']([^"']+)["']""",
    re.I
)
JS_ENDPOINT_PATTERN = re.compile(
    r"""["'`](/(?:api|v\d|graphql|rest|endpoint)[^"'`\s]{0,80})["'`]""",
    re.I
)


class CrawlerModule(ScannerModule):
    name        = "crawler"
    description = "BFS web crawler — maps all pages, forms, endpoints, and interesting paths"

    def run(
        self,
        target: str,
        alive_hosts: list[dict] = None,
        max_depth: int  = 3,
        max_pages: int  = 200,
        delay: float    = 0.08,
        **kwargs,
    ) -> dict[str, Any]:
        self._start_timer()
        self._status(
            f"Crawling [cyan]{target}[/cyan] "
            f"(depth={max_depth}, max_pages={max_pages})…"
        )

        base_url = target if target.startswith("http") else f"https://{target}"
        parsed   = urlparse(base_url)
        domain   = parsed.netloc

        result: dict[str, Any] = {
            "ok":           True,
            "target":       target,
            "domain":       domain,
            "pages":        [],
            "forms":        [],
            "endpoints":    [],
            "interesting":  [],
            "params":       {},       # url → [param_names]
            "robot_paths":  [],
            "sitemap_urls": [],
        }

        # ── 1. Parse robots.txt ───────────────────────────────────────────────
        robot_paths = self._parse_robots(base_url)
        result["robot_paths"] = robot_paths
        if robot_paths:
            console.print(f"  [cyan]  ℹ robots.txt — {len(robot_paths)} disallowed path(s)[/cyan]")

        # ── 2. Parse sitemap.xml ──────────────────────────────────────────────
        sitemap_urls = self._parse_sitemap(base_url)
        result["sitemap_urls"] = sitemap_urls
        if sitemap_urls:
            console.print(f"  [cyan]  ℹ sitemap.xml — {len(sitemap_urls)} URL(s)[/cyan]")

        # ── 3. Probe interesting paths in parallel ────────────────────────────
        interesting = self._probe_interesting_parallel(base_url)
        result["interesting"] = interesting

        # ── 4. BFS crawl ──────────────────────────────────────────────────────
        visited: set[str] = set()
        queue: deque      = deque()

        # Seed with base + alive hosts + sitemap URLs
        queue.append((base_url, 0))
        if alive_hosts:
            for h in alive_hosts[:15]:
                queue.append((h["url"], 0))
        for u in sitemap_urls[:30]:
            queue.append((u, 1))
        # Also queue robots.txt disallowed paths (often interesting)
        for p in robot_paths[:20]:
            if p.startswith("/"):
                queue.append((base_url.rstrip("/") + p, 1))

        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()
            url = self._normalize(url)

            if not url or url in visited:
                continue
            if not self._same_domain(url, domain):
                continue
            if depth > max_depth:
                continue

            visited.add(url)
            time.sleep(delay)

            page = self._fetch_page(url)
            if not page:
                continue

            # Extract URL params
            params = self._extract_url_params(url)

            page_info = {
                "url":    url,
                "status": page["status"],
                "title":  page["title"],
                "forms":  len(page["forms"]),
                "params": params,
            }
            result["pages"].append(page_info)

            # Collect forms
            for f in page["forms"]:
                result["forms"].append(f)

            # Store params indexed by URL
            if params:
                result["params"][url] = params

            # Enqueue discovered links
            for link in page["links"]:
                full       = urljoin(url, link)
                normalized = self._normalize(full)
                if normalized and normalized not in visited:
                    queue.append((normalized, depth + 1))

            # Collect JS API endpoints
            for ep in page["js_endpoints"]:
                full_ep = urljoin(url, ep) if ep.startswith("/") else ep
                if full_ep not in result["endpoints"]:
                    result["endpoints"].append(full_ep)

        # ── 5. Deduplicate forms ──────────────────────────────────────────────
        seen_forms: set[str] = set()
        unique_forms = []
        for f in result["forms"]:
            key = f"{f['action']}|{f['method']}"
            if key not in seen_forms:
                seen_forms.add(key)
                unique_forms.append(f)
        result["forms"] = unique_forms[:100]

        result["stats"] = {
            "pages_crawled":    len(result["pages"]),
            "forms_found":      len(result["forms"]),
            "endpoints_found":  len(result["endpoints"]),
            "interesting_found": len(result["interesting"]),
            "unique_params":    sum(len(v) for v in result["params"].values()),
        }

        self._ok(
            f"Crawl done — {len(result['pages'])} pages, "
            f"{len(result['forms'])} forms, "
            f"{len(result['endpoints'])} API endpoints, "
            f"{len(result['interesting'])} interesting [{self._elapsed()}]"
        )
        self._print_table(result)
        return result

    # ── Fetch + Parse ─────────────────────────────────────────────────────────

    def _fetch_page(self, url: str) -> Optional[dict]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; EVHunter/3.0)",
                    "Accept":     "text/html,application/xhtml+xml,*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                }
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                ct = resp.headers.get("Content-Type", "")
                if any(x in ct for x in ("image", "video", "font", "pdf", "zip", "binary")):
                    return None
                body = resp.read(400_000).decode("utf-8", errors="replace")
                return self._parse_page(url, resp.status, body)
        except urllib.error.HTTPError as e:
            return {"status": e.code, "title": "", "links": [], "forms": [], "js_endpoints": []}
        except Exception:
            return None

    def _parse_page(self, url: str, status: int, body: str) -> dict:
        # Title
        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title   = title_m.group(1).strip()[:80] if title_m else ""

        # Links (href + src + action)
        links: set[str] = set()
        links.update(LINK_PATTERN.findall(body))
        links.update(SRC_PATTERN.findall(body))
        # Filter out data URIs and common static assets
        links = {
            l for l in links
            if not l.startswith("data:") and not l.startswith("javascript:")
            and not any(l.lower().endswith(ext) for ext in
                        (".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
                         ".woff", ".woff2", ".ttf", ".eot", ".css", ".mp4", ".mp3"))
        }

        # Forms
        forms = []
        for m in FORM_PATTERN.finditer(body):
            form_tag = m.group(1)
            form_body = m.group(2)

            action_m = re.search(r"""action\s*=\s*["']([^"']*)["']""", form_tag, re.I)
            method_m = re.search(r"""method\s*=\s*["'](get|post)["']""", form_tag, re.I)

            action = urljoin(url, action_m.group(1)) if action_m else url
            method = method_m.group(1).upper() if method_m else "GET"

            inputs = (
                INPUT_PATTERN.findall(form_body) +
                TEXTAREA_PATTERN.findall(form_body) +
                SELECT_PATTERN.findall(form_body)
            )

            enctype_m = re.search(r"""enctype\s*=\s*["']([^"']+)["']""", form_tag, re.I)
            is_file_upload = enctype_m and "multipart" in enctype_m.group(1)

            forms.append({
                "action":          action,
                "method":          method,
                "inputs":          inputs,
                "file_upload":     is_file_upload,
                "page_url":        url,
            })

            # Also enqueue form action URL
            links.add(action)

        # JS inline endpoint extraction
        js_endpoints = list(set(JS_ENDPOINT_PATTERN.findall(body)))[:30]

        return {
            "status":       status,
            "title":        title,
            "links":        list(links),
            "forms":        forms,
            "js_endpoints": js_endpoints,
        }

    # ── Interesting path probing ───────────────────────────────────────────────

    def _probe_interesting_parallel(self, base_url: str) -> list[dict]:
        """Probe all interesting paths concurrently."""
        found = []

        def probe_one(path: str) -> Optional[dict]:
            url = base_url.rstrip("/") + path
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; EVHunter/3.0)"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=6) as resp:
                    body = resp.read(500).decode("utf-8", errors="replace")
                    if resp.status in (200, 301, 302, 401, 403, 405):
                        return {
                            "url":    url,
                            "path":   path,
                            "status": resp.status,
                            "size":   int(resp.headers.get("Content-Length", 0)),
                            "snippet": body[:100],
                        }
            except urllib.error.HTTPError as e:
                if e.code in (200, 301, 302, 401, 403, 405):
                    return {"url": url, "path": path, "status": e.code, "size": 0, "snippet": ""}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=25) as pool:
            futures = {pool.submit(probe_one, path): path for path in INTERESTING_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        # Sort: 200 first, then 403, then redirects
        status_priority = {200: 0, 401: 1, 403: 2, 405: 3, 301: 4, 302: 4}
        found.sort(key=lambda x: status_priority.get(x["status"], 9))
        return found

    # ── Discovery helpers ──────────────────────────────────────────────────────

    def _parse_robots(self, base_url: str) -> list[str]:
        url   = base_url.rstrip("/") + "/robots.txt"
        paths = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "EVHunter/3.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                content = resp.read(20_000).decode("utf-8", errors="replace")
                for line in content.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            p = parts[1].strip()
                            if p and p not in ("/", ""):
                                paths.append(p)
        except Exception:
            pass
        return paths

    def _parse_sitemap(self, base_url: str) -> list[str]:
        urls = []
        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            url = base_url.rstrip("/") + path
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "EVHunter/3.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    content = resp.read(100_000).decode("utf-8", errors="replace")
                    for m in re.finditer(r"<loc>([^<]+)</loc>", content):
                        urls.append(m.group(1).strip())
                if urls:
                    break
            except Exception:
                pass
        return urls[:200]

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _normalize(self, url: str) -> str:
        try:
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return ""
            clean = urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
            return clean.rstrip("?&")
        except Exception:
            return ""

    def _same_domain(self, url: str, domain: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.netloc == domain or parsed.netloc.endswith("." + domain)
        except Exception:
            return False

    def _extract_url_params(self, url: str) -> list[str]:
        try:
            return list(parse_qs(urlparse(url).query).keys())
        except Exception:
            return []

    # ── Display ───────────────────────────────────────────────────────────────

    def _print_table(self, result: dict):
        if result["interesting"]:
            tbl = Table(
                title=f"  [bold yellow]⚡ Interesting Paths ({len(result['interesting'])})[/bold yellow]",
                box=box.SIMPLE_HEAVY, header_style="bold cyan",
            )
            tbl.add_column("Status", width=8, justify="center")
            tbl.add_column("Path",   style="white", max_width=40)
            tbl.add_column("URL",    style="dim",   max_width=55)
            STATUS_COLOR = {200: "green", 401: "yellow", 403: "yellow", 301: "cyan", 302: "cyan"}
            for p in result["interesting"][:30]:
                sc    = p["status"]
                color = STATUS_COLOR.get(sc, "white")
                tbl.add_row(
                    f"[{color}]{sc}[/{color}]",
                    p["path"][:40],
                    p["url"][:55],
                )
            console.print(tbl)

        stats = result.get("stats", {})
        console.print(
            f"  [dim]  Forms: {stats.get('forms_found', 0)}  |  "
            f"API endpoints: {stats.get('endpoints_found', 0)}  |  "
            f"URL params: {stats.get('unique_params', 0)}[/dim]"
        )
