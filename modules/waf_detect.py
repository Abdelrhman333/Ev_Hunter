"""
EVHunter — WAF / CDN Detection Module
Fingerprints Web Application Firewalls and CDN providers
using header analysis, cookie names, error page patterns,
and response behavior to malicious payloads.
"""

import re
import urllib.error
import urllib.request
from typing import Any

from rich.console import Console
from rich import box
from rich.table import Table

from .base import ScannerModule

console = Console()

# ── Fingerprint signatures ────────────────────────────────────────────────────

WAF_SIGNATURES: list[dict] = [
    {
        "name": "Cloudflare",
        "type": "CDN/WAF",
        "headers":  {"server": "cloudflare", "cf-ray": ""},
        "cookies":  ["__cfduid", "cf_clearance"],
        "patterns": ["cloudflare", "Attention Required!"],
    },
    {
        "name": "AWS CloudFront",
        "type": "CDN",
        "headers":  {"x-amz-cf-id": "", "via": "cloudfront"},
        "cookies":  [],
        "patterns": ["CloudFront"],
    },
    {
        "name": "Akamai",
        "type": "CDN/WAF",
        "headers":  {"x-check-cacheable": "", "akamai-grn": ""},
        "cookies":  ["ak_bmsc", "bm_sz"],
        "patterns": ["AkamaiGHost", "Reference #"],
    },
    {
        "name": "Fastly",
        "type": "CDN",
        "headers":  {"x-fastly-request-id": "", "via": "varnish"},
        "cookies":  [],
        "patterns": ["Fastly error"],
    },
    {
        "name": "Imperva / Incapsula",
        "type": "WAF",
        "headers":  {"x-iinfo": "", "x-cdn": "imperva"},
        "cookies":  ["incap_ses_", "visid_incap_"],
        "patterns": ["Incapsula incident", "_Incapsula_Resource"],
    },
    {
        "name": "ModSecurity",
        "type": "WAF",
        "headers":  {"server": "mod_security"},
        "cookies":  [],
        "patterns": ["ModSecurity Action", "Not Acceptable"],
    },
    {
        "name": "Sucuri",
        "type": "WAF",
        "headers":  {"x-sucuri-id": "", "server": "sucuri"},
        "cookies":  [],
        "patterns": ["Sucuri WebSite Firewall"],
    },
    {
        "name": "F5 BIG-IP ASM",
        "type": "WAF",
        "headers":  {"x-wa-info": "", "server": "BigIP"},
        "cookies":  ["TS", "BIGipServer"],
        "patterns": ["The requested URL was rejected"],
    },
    {
        "name": "Barracuda",
        "type": "WAF",
        "headers":  {"server": "barracuda"},
        "cookies":  ["barra_counter_session"],
        "patterns": ["Barracuda Networks"],
    },
    {
        "name": "Nginx",
        "type": "Server",
        "headers":  {"server": "nginx"},
        "cookies":  [],
        "patterns": [],
    },
    {
        "name": "Apache",
        "type": "Server",
        "headers":  {"server": "apache"},
        "cookies":  [],
        "patterns": [],
    },
]

# Payloads that commonly trigger WAF 403/406/429
WAF_PROBE_PAYLOADS = [
    "/?q=<script>alert(1)</script>",
    "/?id=1 UNION SELECT 1,2,3--",
    "/?file=../../etc/passwd",
    "/?cmd=;ls%20-la",
]


class WAFDetectModule(ScannerModule):
    name        = "waf"
    description = "WAF and CDN fingerprinting via headers, cookies, and behavior"

    def run(self, target: str, **kwargs) -> dict[str, Any]:
        self._start_timer()
        self._status(f"WAF/CDN detection on [cyan]{target}[/cyan]…")

        result: dict[str, Any] = {
            "ok":       True,
            "target":   target,
            "detected": [],
            "bypassed": False,
            "raw_headers": {},
            "behavior": {},
        }

        url  = target if target.startswith("http") else f"https://{target}"
        base = self._fetch(url)

        if base is None:
            url  = f"http://{target}" if not target.startswith("http") else url
            base = self._fetch(url)

        if base is None:
            result["ok"]    = False
            result["error"] = "Could not connect"
            self._warn("Could not connect for WAF detection")
            return result

        headers     = base["headers"]
        cookies_str = headers.get("set-cookie", "")
        body        = base["body"]
        result["raw_headers"] = headers

        # ── Header / cookie / body fingerprinting ─────────────────────────────
        for sig in WAF_SIGNATURES:
            score = 0

            for hdr_key, hdr_val in sig["headers"].items():
                actual = headers.get(hdr_key, "").lower()
                if hdr_val == "":
                    if actual:
                        score += 2
                elif hdr_val.lower() in actual:
                    score += 3

            for cookie in sig["cookies"]:
                if cookie.lower() in cookies_str.lower():
                    score += 3

            for pattern in sig["patterns"]:
                if pattern.lower() in body.lower():
                    score += 2

            if score >= 2:
                result["detected"].append({
                    "name":  sig["name"],
                    "type":  sig["type"],
                    "score": score,
                })

        # ── Behavioral probing ────────────────────────────────────────────────
        blocked_count = 0
        for payload in WAF_PROBE_PAYLOADS:
            probe_url = url.rstrip("/") + payload
            probe     = self._fetch(probe_url, follow=False)
            if probe and probe["status"] in (403, 406, 429, 503):
                blocked_count += 1

        result["behavior"]["blocked_probes"] = blocked_count
        result["behavior"]["total_probes"]   = len(WAF_PROBE_PAYLOADS)

        if blocked_count >= 2 and not result["detected"]:
            result["detected"].append({
                "name":  "Unknown WAF",
                "type":  "WAF",
                "score": blocked_count,
            })

        # Deduplicate by name, keep highest score
        seen: dict[str, dict] = {}
        for d in result["detected"]:
            n = d["name"]
            if n not in seen or d["score"] > seen[n]["score"]:
                seen[n] = d
        result["detected"] = sorted(seen.values(), key=lambda x: -x["score"])

        self._ok(f"WAF/CDN detection done — "
                 f"{len(result['detected'])} component(s) found [{self._elapsed()}]")
        self._print_table(result)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _fetch(self, url: str, follow: bool = True) -> dict | None:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept":     "text/html,application/xhtml+xml",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body    = resp.read(2048).decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                return {"status": resp.status, "headers": headers, "body": body}
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in dict(e.headers).items()}
            body    = e.read(512).decode("utf-8", errors="replace") if e.fp else ""
            return {"status": e.code, "headers": headers, "body": body}
        except Exception:
            return None

    def _print_table(self, result: dict):
        if not result["detected"]:
            console.print("  [dim]  No WAF/CDN detected[/dim]")
            return
        tbl = Table(box=box.SIMPLE, header_style="bold cyan")
        tbl.add_column("Component", style="white")
        tbl.add_column("Type",      style="dim")
        tbl.add_column("Confidence")
        for d in result["detected"]:
            score = d["score"]
            conf  = "High" if score >= 6 else "Medium" if score >= 3 else "Low"
            color = "green" if score >= 6 else "yellow" if score >= 3 else "dim"
            tbl.add_row(d["name"], d["type"], f"[{color}]{conf}[/{color}]")
        console.print(tbl)
