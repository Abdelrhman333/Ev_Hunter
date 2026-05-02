"""
EVHunter — Technology Detection Module
Fingerprints the tech stack from HTTP headers, cookies,
HTML patterns, and meta tags. No Wappalyzer dependency.
"""

import re
import urllib.request
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

# ── Fingerprint database ──────────────────────────────────────────────────────
# Each entry: (tech_name, category, checks)
# checks: {"header": {hdr_name: regex}, "cookie": name_pattern, "body": regex, "meta": regex}

TECH_FINGERPRINTS: list[dict] = [
    # Servers
    {"name":"nginx",              "cat":"Server",   "header":{"server":r"nginx"},              "body": None, "cookie": None},
    {"name":"Apache",             "cat":"Server",   "header":{"server":r"apache"},             "body": None, "cookie": None},
    {"name":"IIS",                "cat":"Server",   "header":{"server":r"Microsoft-IIS"},       "body": None, "cookie": None},
    {"name":"Caddy",              "cat":"Server",   "header":{"server":r"Caddy"},              "body": None, "cookie": None},
    {"name":"Gunicorn",           "cat":"Server",   "header":{"server":r"gunicorn"},           "body": None, "cookie": None},
    {"name":"LiteSpeed",          "cat":"Server",   "header":{"server":r"LiteSpeed"},          "body": None, "cookie": None},
    # Frameworks
    {"name":"Django",             "cat":"Framework","header":{"x-frame-options":r"SAMEORIGIN"},"body": r"csrfmiddlewaretoken", "cookie": "csrftoken"},
    {"name":"Ruby on Rails",      "cat":"Framework","header":{},"body":r"csrf-token.*rails",    "cookie": "_session_id"},
    {"name":"Laravel",            "cat":"Framework","header":{},"body":None,                   "cookie": "laravel_session"},
    {"name":"Express.js",         "cat":"Framework","header":{"x-powered-by":r"Express"},      "body": None, "cookie": None},
    {"name":"ASP.NET",            "cat":"Framework","header":{"x-powered-by":r"ASP\.NET"},     "body": None, "cookie": "ASP.NET_SessionId"},
    {"name":"Spring",             "cat":"Framework","header":{"x-application-context":r".*"},  "body": None, "cookie": "JSESSIONID"},
    {"name":"WordPress",          "cat":"CMS",      "header":{},"body":r"/wp-content/",        "cookie": "wordpress_"},
    {"name":"Drupal",             "cat":"CMS",      "header":{"x-generator":r"Drupal"},        "body": r'<meta name="Generator" content="Drupal', "cookie": "Drupal.tableDrag"},
    {"name":"Joomla",             "cat":"CMS",      "header":{},"body":r"/media/jui/",         "cookie": None},
    {"name":"Shopify",            "cat":"eCommerce","header":{"x-shopid":r".*"},               "body": r'cdn\.shopify\.com', "cookie": "_shopify_"},
    {"name":"Magento",            "cat":"eCommerce","header":{},"body":r"Mage\.Cookies",       "cookie": "frontend"},
    {"name":"WooCommerce",        "cat":"eCommerce","header":{},"body":r"woocommerce",         "cookie": "woocommerce_"},
    # Databases / backends (via headers only)
    {"name":"GraphQL",            "cat":"API",      "header":{},"body":r'"__schema"|graphiql', "cookie": None},
    {"name":"Swagger UI",         "cat":"API",      "header":{},"body":r'swagger-ui',          "cookie": None},
    # Security headers
    {"name":"HSTS",               "cat":"Security", "header":{"strict-transport-security":r"max-age"}, "body": None, "cookie": None},
    {"name":"CSP",                "cat":"Security", "header":{"content-security-policy":r".*"},         "body": None, "cookie": None},
    {"name":"X-Frame-Options",    "cat":"Security", "header":{"x-frame-options":r"DENY|SAMEORIGIN"},    "body": None, "cookie": None},
    # CDN
    {"name":"Cloudflare",         "cat":"CDN",      "header":{"server":r"cloudflare","cf-ray":r".*"},   "body": None, "cookie": None},
    {"name":"Fastly",             "cat":"CDN",      "header":{"x-fastly-request-id":r".*"},             "body": None, "cookie": None},
    {"name":"Varnish",            "cat":"CDN",      "header":{"x-varnish":r".*","via":r"varnish"},      "body": None, "cookie": None},
    # JS frameworks (body only)
    {"name":"React",              "cat":"JS",       "header":{},"body":r'__react|data-reactroot',        "cookie": None},
    {"name":"Vue.js",             "cat":"JS",       "header":{},"body":r'__vue__|data-v-',               "cookie": None},
    {"name":"Angular",            "cat":"JS",       "header":{},"body":r'ng-version=|angular\.min\.js',  "cookie": None},
    {"name":"Next.js",            "cat":"JS",       "header":{"x-powered-by":r"Next\.js"},"body":r'__NEXT_DATA__', "cookie": None},
    {"name":"Nuxt.js",            "cat":"JS",       "header":{},"body":r'__nuxt|__NUXT',                 "cookie": None},
    {"name":"jQuery",             "cat":"JS",       "header":{},"body":r'jquery(?:\.min)?\.js',           "cookie": None},
    # Analytics
    {"name":"Google Analytics",   "cat":"Analytics","header":{},"body":r'google-analytics\.com/(?:ga\.js|analytics\.js|gtag)', "cookie": None},
    {"name":"GTM",                "cat":"Analytics","header":{},"body":r'googletagmanager\.com/gtm\.js', "cookie": None},
]


class TechDetectModule(ScannerModule):
    name        = "tech"
    description = "Technology stack fingerprinting from headers, cookies, and HTML"

    def run(self, target: str, urls: list[str] = None, **kwargs) -> dict[str, Any]:
        self._start_timer()
        self._status(f"Tech detection on [cyan]{target}[/cyan]…")

        test_urls = urls or [
            target if target.startswith("http") else f"https://{target}",
        ]

        all_tech: dict[str, dict] = {}

        for url in test_urls[:5]:
            detected = self._detect(url)
            for t in detected:
                n = t["name"]
                if n not in all_tech or t["confidence"] > all_tech[n]["confidence"]:
                    all_tech[n] = t

        result: dict[str, Any] = {
            "ok":      True,
            "target":  target,
            "tech":    list(all_tech.values()),
        }

        self._ok(
            f"Tech detection done — {len(result['tech'])} technolog(ies) found [{self._elapsed()}]"
        )
        self._print_table(result)
        return result

    # ── Core detection ────────────────────────────────────────────────────────

    def _detect(self, url: str) -> list[dict]:
        data = self._fetch(url)
        if not data:
            return []

        headers  = data["headers"]
        body     = data["body"]
        cookies  = data["cookies"]
        detected = []

        for fp in TECH_FINGERPRINTS:
            score = 0

            # Header checks
            for hdr, pattern in fp.get("header", {}).items():
                val = headers.get(hdr.lower(), "")
                if val and re.search(pattern, val, re.I):
                    score += 3

            # Cookie check
            ck_pattern = fp.get("cookie")
            if ck_pattern and any(ck_pattern.lower() in c.lower() for c in cookies):
                score += 2

            # Body check
            body_pattern = fp.get("body")
            if body_pattern and body and re.search(body_pattern, body, re.I):
                score += 2

            if score > 0:
                detected.append({
                    "name":       fp["name"],
                    "category":   fp["cat"],
                    "confidence": min(score * 20, 100),
                    "url":        url,
                })

        return detected

    def _fetch(self, url: str) -> dict | None:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 EVHunter/2.0", "Accept": "text/html,*/*"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                # Parse cookies from set-cookie header
                raw_cookies = resp.headers.get_all("Set-Cookie") or []
                cookies     = [c.split(";")[0].split("=")[0].strip() for c in raw_cookies]
                body        = resp.read(100_000).decode("utf-8", errors="replace")
                return {"headers": headers, "cookies": cookies, "body": body}
        except Exception:
            return None

    def _print_table(self, result: dict):
        tech_by_cat: dict[str, list] = {}
        for t in result["tech"]:
            cat = t["category"]
            tech_by_cat.setdefault(cat, []).append(t)

        if not tech_by_cat:
            console.print("  [dim]  No tech detected[/dim]")
            return

        tbl = Table(box=box.SIMPLE, header_style="bold cyan")
        tbl.add_column("Category",   width=12, style="dim")
        tbl.add_column("Technology", style="white")
        tbl.add_column("Confidence", width=10)

        for cat in ("Server", "Framework", "CMS", "eCommerce", "API", "JS", "CDN", "Security", "Analytics"):
            for t in tech_by_cat.get(cat, []):
                conf  = t["confidence"]
                color = "green" if conf >= 60 else "yellow"
                tbl.add_row(cat, t["name"], f"[{color}]{conf}%[/{color}]")
        console.print(tbl)
