"""
EVHunter — Parameter Discovery Module  v1.0
Discovers hidden GET/POST parameters on endpoints.

Techniques:
  - Wordlist-based parameter guessing
  - Response comparison (length, status, content diff)
  - Reflected parameter detection (XSS surface)
  - Common param patterns per endpoint type (login, search, api, etc.)
  - Form parameter augmentation
"""

import re
import time
import urllib.error
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

# ── Parameter wordlists ───────────────────────────────────────────────────────

COMMON_PARAMS = [
    # Auth / session
    "id", "user", "username", "userid", "user_id", "uid",
    "email", "password", "pass", "token", "key", "apikey", "api_key",
    "secret", "auth", "session", "sessionid", "session_id",
    # Navigation / redirect
    "url", "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "returnUrl", "returnTo", "next", "continue",
    "destination", "dest", "forward", "goto", "go", "target",
    "ref", "referrer", "referer", "from", "to", "link", "location",
    "out", "redir", "rdir", "uri",
    # IDOR / object
    "id", "item", "item_id", "record", "record_id", "order",
    "order_id", "account", "account_id", "product", "product_id",
    "file", "filename", "path", "page", "document", "doc",
    "report", "invoice", "ticket",
    # SSRF / path
    "host", "server", "proxy", "service", "endpoint", "backend",
    "domain", "url", "src", "source", "image", "avatar", "icon",
    "callback", "hook", "webhook",
    # Search / query
    "q", "query", "search", "s", "keyword", "term", "find",
    "filter", "sort", "order", "by", "limit", "offset", "page",
    "per_page", "count", "size",
    # File / path traversal
    "file", "path", "dir", "directory", "folder", "read",
    "load", "include", "require", "import", "template", "view",
    "layout", "config",
    # SQL / injection
    "id", "name", "type", "category", "cat", "tag", "status",
    "active", "enabled", "visible",
    # Debug
    "debug", "test", "verbose", "log", "trace", "format", "output",
    "callback", "jsonp", "lang", "locale", "currency",
    # API
    "version", "v", "format", "fields", "expand", "include",
    "exclude", "select", "projection",
]

# Payloads to detect reflection
REFLECTION_PAYLOAD = "evhunter9x8z"

# Param fingerprints per endpoint type
ENDPOINT_PARAMS = {
    "login":    ["username", "password", "email", "user", "pass", "remember", "redirect"],
    "search":   ["q", "query", "s", "search", "keyword", "term", "filter"],
    "api":      ["id", "user_id", "token", "format", "version", "fields", "include"],
    "upload":   ["file", "filename", "type", "dest", "path"],
    "download": ["file", "id", "path", "filename", "token"],
    "redirect": ["url", "redirect", "next", "return", "to", "goto", "dest"],
    "profile":  ["id", "user", "username", "userid", "account"],
    "admin":    ["id", "action", "user", "module", "tab", "section"],
}


class ParamDiscoveryModule(ScannerModule):
    name        = "param_discovery"
    description = "Hidden parameter discovery via wordlist fuzzing and response analysis"

    def run(
        self,
        target: str,
        urls: list[str]              = None,
        forms: list[dict]            = None,
        crawler_params: dict         = None,
        max_urls: int                = 20,
        **kwargs,
    ) -> dict[str, Any]:
        self._start_timer()
        self._status(f"Parameter discovery on [cyan]{target}[/cyan]…")

        result: dict[str, Any] = {
            "ok":               True,
            "target":           target,
            "discovered_params": [],
            "reflected_params": [],
            "redirect_params":  [],
            "ssrf_candidates":  [],
        }

        test_urls = (urls or [])[:max_urls]
        if not test_urls:
            base = target if target.startswith("http") else f"https://{target}"
            test_urls = [base]

        # ── 1. Fuzz each URL for hidden GET params ────────────────────────────
        for url in test_urls:
            self._fuzz_url(url, result)

        # ── 2. Augment known forms with extra parameters ──────────────────────
        for form in (forms or [])[:15]:
            self._fuzz_form(form, result)

        # ── 3. Test already-known params from crawler for injection ───────────
        for url, params in (crawler_params or {}).items():
            for param in params:
                finding = self._test_param(url, param)
                if finding:
                    result["discovered_params"].append(finding)

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict] = []
        for p in result["discovered_params"]:
            key = f"{p['url']}|{p['param']}"
            if key not in seen:
                seen.add(key)
                unique.append(p)
        result["discovered_params"] = unique

        total = (
            len(result["discovered_params"]) +
            len(result["reflected_params"]) +
            len(result["redirect_params"]) +
            len(result["ssrf_candidates"])
        )
        self._ok(
            f"Param discovery done — {total} interesting parameter(s) [{self._elapsed()}]"
        )
        self._print_table(result)
        return result

    # ── Core fuzzing logic ────────────────────────────────────────────────────

    def _fuzz_url(self, url: str, result: dict):
        """Get baseline response, then probe parameters."""
        baseline = self._fetch(url)
        if not baseline:
            return

        # Select param list based on endpoint hints
        params = self._select_params(url)

        # Test in batches of 10 (reduce requests)
        batch_size = 10
        for i in range(0, len(params), batch_size):
            batch = params[i: i + batch_size]

            # Test with reflection payload
            test_url = self._build_url(url, {p: REFLECTION_PAYLOAD for p in batch})
            response = self._fetch(test_url)
            if not response:
                continue

            # Check which params were reflected
            if REFLECTION_PAYLOAD in response["body"]:
                # Binary search: find which specific param caused reflection
                for param in batch:
                    single_url = self._build_url(url, {param: REFLECTION_PAYLOAD})
                    single_resp = self._fetch(single_url)
                    if single_resp and REFLECTION_PAYLOAD in single_resp["body"]:
                        result["reflected_params"].append({
                            "url":      url,
                            "param":    param,
                            "severity": "medium",
                            "detail":   f"Parameter '{param}' is reflected in response — potential XSS",
                            "poc_url":  self._build_url(url, {param: "<script>alert(1)</script>"}),
                        })

            # Check status/length differences
            if abs(response["length"] - baseline["length"]) > 100:
                for param in batch:
                    single_url  = self._build_url(url, {param: REFLECTION_PAYLOAD})
                    single_resp = self._fetch(single_url)
                    if single_resp and abs(single_resp["length"] - baseline["length"]) > 50:
                        result["discovered_params"].append({
                            "url":      url,
                            "param":    param,
                            "baseline_len": baseline["length"],
                            "fuzzed_len":   single_resp["length"],
                            "severity": "low",
                            "detail":   f"Parameter '{param}' changes response length ({baseline['length']} → {single_resp['length']})",
                        })

        # ── Redirect param detection ─────────────────────────────────────────
        redirect_params = [
            "url", "redirect", "redirect_uri", "return", "next", "goto",
            "destination", "forward", "to", "continue", "redir",
        ]
        for param in redirect_params:
            test_url = self._build_url(url, {param: "https://evil.com"})
            resp = self._fetch(test_url, follow_redirects=False)
            if resp and resp["status"] in (301, 302, 303, 307, 308):
                location = resp.get("location", "")
                if "evil.com" in location:
                    result["redirect_params"].append({
                        "url":      url,
                        "param":    param,
                        "location": location,
                        "severity": "high",
                        "detail":   f"Open redirect via '{param}' → {location}",
                    })

        # ── SSRF candidate params ────────────────────────────────────────────
        ssrf_params = ["url", "host", "server", "image", "src", "source",
                        "proxy", "callback", "backend", "endpoint", "service"]
        for param in ssrf_params:
            test_url = self._build_url(url, {param: "http://169.254.169.254/latest/meta-data/"})
            resp = self._fetch(test_url)
            if resp and resp["status"] == 200 and (
                "ami-id" in resp["body"] or "instance-id" in resp["body"]
            ):
                result["ssrf_candidates"].append({
                    "url":      url,
                    "param":    param,
                    "severity": "critical",
                    "detail":   f"SSRF confirmed — AWS metadata accessible via '{param}'",
                })

    def _fuzz_form(self, form: dict, result: dict):
        """Test form with extra parameters beyond its known inputs."""
        action  = form.get("action", "")
        method  = form.get("method", "GET")
        inputs  = form.get("inputs", [])

        if not action:
            return

        # Extra params to inject alongside form fields
        extra = [p for p in COMMON_PARAMS if p not in inputs][:20]

        for param in extra:
            data = {i: "test" for i in inputs}
            data[param] = REFLECTION_PAYLOAD

            if method == "POST":
                resp = self._post(action, data)
            else:
                resp = self._fetch(self._build_url(action, data))

            if resp and REFLECTION_PAYLOAD in resp.get("body", ""):
                result["reflected_params"].append({
                    "url":      action,
                    "param":    param,
                    "method":   method,
                    "severity": "medium",
                    "detail":   f"Hidden form param '{param}' is reflected (method={method})",
                })

    def _test_param(self, url: str, param: str) -> Optional[dict]:
        """Test a known param for interesting behavior."""
        baseline = self._fetch(url)
        if not baseline:
            return None

        # Test with reflection payload
        test_url = self._build_url(url, {param: REFLECTION_PAYLOAD})
        resp = self._fetch(test_url)
        if not resp:
            return None

        if REFLECTION_PAYLOAD in resp["body"]:
            return {
                "url":      url,
                "param":    param,
                "severity": "medium",
                "detail":   f"Known param '{param}' reflects input — check for XSS",
            }
        return None

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _fetch(self, url: str, follow_redirects: bool = True) -> Optional[dict]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; EVHunter/3.0)",
                    "Accept":     "*/*",
                }
            )
            if not follow_redirects:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPRedirectHandler()
                )
                # Monkey-patch to NOT follow redirects
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None
                opener = urllib.request.build_opener(NoRedirect)
                try:
                    with opener.open(req, timeout=self.timeout) as resp:
                        body = resp.read(10_000).decode("utf-8", errors="replace")
                        return {
                            "status":   resp.status,
                            "body":     body,
                            "length":   len(body),
                            "location": resp.headers.get("Location", ""),
                        }
                except urllib.error.HTTPError as e:
                    return {
                        "status":   e.code,
                        "body":     "",
                        "length":   0,
                        "location": e.headers.get("Location", ""),
                    }

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(50_000).decode("utf-8", errors="replace")
                return {
                    "status":   resp.status,
                    "body":     body,
                    "length":   len(body),
                    "location": resp.headers.get("Location", ""),
                }
        except urllib.error.HTTPError as e:
            body = e.read(1000).decode("utf-8", errors="replace") if e.fp else ""
            return {"status": e.code, "body": body, "length": len(body), "location": ""}
        except Exception:
            return None

    def _post(self, url: str, data: dict) -> Optional[dict]:
        try:
            encoded = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(
                url,
                data=encoded,
                headers={
                    "User-Agent":   "Mozilla/5.0 (compatible; EVHunter/3.0)",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(50_000).decode("utf-8", errors="replace")
                return {"status": resp.status, "body": body, "length": len(body)}
        except Exception:
            return None

    def _build_url(self, url: str, params: dict) -> str:
        from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
        parsed  = urlparse(url)
        existing = parse_qs(parsed.query, keep_blank_values=True)
        merged  = {k: v[0] if isinstance(v, list) else v for k, v in existing.items()}
        merged.update(params)
        new_query = urlencode(merged)
        return urlunparse(parsed._replace(query=new_query))

    def _select_params(self, url: str) -> list[str]:
        """Return relevant param list based on URL hints."""
        url_lower = url.lower()
        params    = list(COMMON_PARAMS)  # base list

        for key, extra in ENDPOINT_PARAMS.items():
            if key in url_lower:
                params = extra + [p for p in params if p not in extra]
                break

        # Remove duplicates while preserving order
        seen  = set()
        dedup = []
        for p in params:
            if p not in seen:
                seen.add(p)
                dedup.append(p)
        return dedup

    # ── Display ───────────────────────────────────────────────────────────────

    def _print_table(self, result: dict):
        all_findings = (
            result["reflected_params"] +
            result["redirect_params"] +
            result["ssrf_candidates"] +
            result["discovered_params"]
        )
        if not all_findings:
            console.print("  [dim]  No interesting parameters found[/dim]")
            return

        tbl = Table(
            title=f"  [bold]Parameter Findings ({len(all_findings)})[/bold]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
        )
        tbl.add_column("Severity", width=10)
        tbl.add_column("Param",    width=18, style="white")
        tbl.add_column("URL",      max_width=45, style="dim")
        tbl.add_column("Detail",   max_width=45)
        SEV = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        for f in all_findings[:30]:
            sev = f.get("severity", "low")
            tbl.add_row(
                f"[{SEV.get(sev,'white')}]{sev.upper()}[/{SEV.get(sev,'white')}]",
                f.get("param", "?")[:18],
                f.get("url", "?")[:45],
                f.get("detail", "")[:45],
            )
        console.print(tbl)
