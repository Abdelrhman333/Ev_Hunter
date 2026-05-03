"""
EVHunter — Header Injection Module  v1.0
Tests for authentication bypass and cache poisoning via HTTP headers.

Tests:
  - Host header injection → SSRF / password reset poisoning
  - X-Forwarded-For: 127.0.0.1 → IP restriction bypass
  - X-Original-URL / X-Rewrite-URL → path restriction bypass
  - X-Forwarded-Host → cache poisoning
  - Client-IP / True-Client-IP → IP bypass
  - X-Custom-IP-Authorization → WAF bypass
  - Referer / Origin manipulation
  - Method override (X-HTTP-Method-Override)
"""

import re
import urllib.error
import urllib.request
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

EVIL_HOST    = "evil.evhunter.com"
LOOPBACK     = "127.0.0.1"
LOCALHOST    = "localhost"


class HeaderInjectionModule(ScannerModule):
    name        = "header_injection"
    description = "HTTP header injection — auth bypass, SSRF, cache poisoning"

    def run(self, target: str, urls: list[str] = None, **kwargs) -> dict[str, Any]:
        self._start_timer()
        self._status(f"Header injection testing on [cyan]{target}[/cyan]…")

        base_url  = target if target.startswith("http") else f"https://{target}"
        test_urls = (urls or [base_url])[:10]

        result: dict[str, Any] = {
            "ok":              True,
            "target":          target,
            "vulnerabilities": [],
            "summary":         "",
        }

        for url in test_urls:
            self._test_host_header(url, result)
            self._test_ip_bypass(url, result)
            self._test_path_override(url, result)
            self._test_method_override(url, result)
            self._test_cache_poisoning(url, result)
            self._test_cors_origin(url, result)

        if result["vulnerabilities"]:
            result["summary"] = (
                f"Found {len(result['vulnerabilities'])} header injection vulnerability(ies)"
            )
        else:
            result["summary"] = "No header injection vulnerabilities detected"

        self._ok(
            f"Header injection done — "
            f"{len(result['vulnerabilities'])} issue(s) [{self._elapsed()}]"
        )
        self._print_table(result)
        return result

    # ── Individual tests ──────────────────────────────────────────────────────

    def _test_host_header(self, url: str, result: dict):
        """Host header injection — password reset poisoning / SSRF."""
        baseline = self._fetch(url)
        if not baseline:
            return

        for evil_host in (EVIL_HOST, f"{EVIL_HOST}:80", f"@{EVIL_HOST}"):
            resp = self._fetch(url, extra_headers={"Host": evil_host})
            if not resp:
                continue

            # Check if evil host appears in response (reflected)
            if evil_host in resp["body"] or EVIL_HOST in resp["body"]:
                result["vulnerabilities"].append({
                    "type":     "Host Header Injection",
                    "header":   "Host",
                    "value":    evil_host,
                    "url":      url,
                    "severity": "high",
                    "evidence": f"Evil host reflected in response body",
                    "curl_poc": (
                        f"curl -sk -H 'Host: {evil_host}' '{url}' | grep '{EVIL_HOST}'"
                    ),
                    "detail": (
                        "Host header injection detected — may enable password reset "
                        "poisoning (victim receives link to attacker domain)"
                    ),
                })
                break

            # Status changes (200 → 500 might indicate SSRF attempt)
            if baseline["status"] == 200 and resp["status"] >= 500:
                result["vulnerabilities"].append({
                    "type":     "Host Header SSRF (Error-Based)",
                    "header":   "Host",
                    "value":    evil_host,
                    "url":      url,
                    "severity": "medium",
                    "evidence": f"Status changed: {baseline['status']} → {resp['status']}",
                    "curl_poc": f"curl -sk -H 'Host: {evil_host}' '{url}'",
                    "detail":   "Server responds differently to injected Host — possible SSRF",
                })

    def _test_ip_bypass(self, url: str, result: dict):
        """Test IP restriction bypass via forwarding headers."""
        # First get baseline to see if there's a restriction to bypass
        baseline = self._fetch(url)
        if not baseline:
            return

        bypass_headers_sets = [
            {"X-Forwarded-For":        LOOPBACK},
            {"X-Real-IP":              LOOPBACK},
            {"Client-IP":              LOOPBACK},
            {"True-Client-IP":         LOOPBACK},
            {"X-Client-IP":            LOOPBACK},
            {"X-Cluster-Client-IP":    LOOPBACK},
            {"X-Custom-IP-Authorization": LOOPBACK},
            {"Forwarded":              f"for={LOOPBACK}"},
            # Try the full localhost chain
            {"X-Forwarded-For":        f"{LOOPBACK}, 10.0.0.1"},
        ]

        for headers in bypass_headers_sets:
            resp = self._fetch(url, extra_headers=headers)
            if not resp:
                continue

            # If page was restricted (403/401) and now we get 200 → bypass!
            if baseline["status"] in (403, 401, 429) and resp["status"] == 200:
                header_name  = list(headers.keys())[0]
                header_value = list(headers.values())[0]
                result["vulnerabilities"].append({
                    "type":     "IP Restriction Bypass",
                    "header":   header_name,
                    "value":    header_value,
                    "url":      url,
                    "severity": "high",
                    "evidence": f"Status: {baseline['status']} → {resp['status']} with spoofed IP",
                    "curl_poc": (
                        f"curl -sk -H '{header_name}: {header_value}' '{url}'"
                    ),
                    "detail": (
                        f"Access restriction bypassed by setting {header_name}: {header_value}"
                    ),
                })

            # If currently 200 and response body changes significantly (admin content?)
            elif baseline["status"] == 200 and resp["status"] == 200:
                if abs(resp["length"] - baseline["length"]) > 500:
                    header_name  = list(headers.keys())[0]
                    header_value = list(headers.values())[0]
                    result["vulnerabilities"].append({
                        "type":     "IP Header Response Difference",
                        "header":   header_name,
                        "value":    header_value,
                        "url":      url,
                        "severity": "low",
                        "evidence": (
                            f"Response length changed: {baseline['length']} → {resp['length']}"
                        ),
                        "curl_poc": (
                            f"curl -sk -H '{header_name}: {header_value}' '{url}'"
                        ),
                        "detail": "Response differs when spoofing IP — investigate manually",
                    })

    def _test_path_override(self, url: str, result: dict):
        """Test X-Original-URL and X-Rewrite-URL for path restriction bypass."""
        # Target a known-restricted path
        admin_paths = ["/admin", "/administrator", "/manage", "/internal"]

        baseline = self._fetch(url)
        if not baseline:
            return

        for admin_path in admin_paths:
            for override_header in (
                "X-Original-URL",
                "X-Rewrite-URL",
                "X-Override-URL",
            ):
                resp = self._fetch(url, extra_headers={override_header: admin_path})
                if not resp:
                    continue

                # If we get different (possibly admin) content
                if resp["status"] == 200 and baseline["status"] in (403, 404):
                    result["vulnerabilities"].append({
                        "type":     f"Path Override via {override_header}",
                        "header":   override_header,
                        "value":    admin_path,
                        "url":      url,
                        "severity": "high",
                        "evidence": f"Status {baseline['status']} → 200 with header override",
                        "curl_poc": (
                            f"curl -sk -H '{override_header}: {admin_path}' '{url}'"
                        ),
                        "detail": (
                            f"Access control bypass: {override_header} overrides "
                            f"the request path to {admin_path}"
                        ),
                    })

    def _test_method_override(self, url: str, result: dict):
        """Test HTTP method override — may bypass WAF or enable DELETE/PUT."""
        override_headers = [
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-Method-Override",      "PUT"),
            ("X-HTTP-Method",          "DELETE"),
            ("_method",                "DELETE"),  # form field override
        ]

        baseline = self._fetch(url)
        if not baseline:
            return

        for header, value in override_headers:
            resp = self._fetch(url, extra_headers={header: value})
            if not resp:
                continue

            # If response changes significantly
            if resp["status"] != baseline["status"]:
                result["vulnerabilities"].append({
                    "type":     "HTTP Method Override",
                    "header":   header,
                    "value":    value,
                    "url":      url,
                    "severity": "medium",
                    "evidence": f"Status changed: {baseline['status']} → {resp['status']}",
                    "curl_poc": (
                        f"curl -sk -H '{header}: {value}' '{url}'"
                    ),
                    "detail": f"Server respects {header} override — may allow unintended HTTP methods",
                })

    def _test_cache_poisoning(self, url: str, result: dict):
        """Test for cache poisoning via X-Forwarded-Host."""
        baseline = self._fetch(url)
        if not baseline:
            return

        resp = self._fetch(url, extra_headers={"X-Forwarded-Host": EVIL_HOST})
        if not resp:
            return

        # Check if evil host is reflected in response
        if EVIL_HOST in resp["body"]:
            result["vulnerabilities"].append({
                "type":     "Cache Poisoning via X-Forwarded-Host",
                "header":   "X-Forwarded-Host",
                "value":    EVIL_HOST,
                "url":      url,
                "severity": "high",
                "evidence": f"X-Forwarded-Host value reflected in response body",
                "curl_poc": (
                    f"curl -sk -H 'X-Forwarded-Host: {EVIL_HOST}' '{url}'"
                ),
                "detail": (
                    "X-Forwarded-Host is reflected in the response. If cached, "
                    "subsequent users may receive malicious content from the attacker's domain."
                ),
            })

    def _test_cors_origin(self, url: str, result: dict):
        """Test for arbitrary Origin reflection."""
        test_origins = [
            f"https://{EVIL_HOST}",
            "null",
            "https://evil.com",
        ]

        for origin in test_origins:
            resp = self._fetch(url, extra_headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.get("acao", "")
            acac = resp.get("acac", "").lower()

            if acao == origin and acac == "true":
                result["vulnerabilities"].append({
                    "type":     "CORS: Arbitrary Origin + Credentials",
                    "header":   "Origin",
                    "value":    origin,
                    "url":      url,
                    "severity": "critical",
                    "evidence": f"ACAO: {acao}, ACAC: {acac}",
                    "curl_poc": (
                        f"curl -sk -H 'Origin: {origin}' '{url}' -I | grep -i 'access-control'"
                    ),
                    "detail": "Arbitrary origin reflected with credentials — attacker can steal authenticated responses",
                })
            elif acao == origin:
                result["vulnerabilities"].append({
                    "type":     "CORS: Arbitrary Origin Reflection",
                    "header":   "Origin",
                    "value":    origin,
                    "url":      url,
                    "severity": "high",
                    "evidence": f"ACAO: {acao}",
                    "curl_poc": (
                        f"curl -sk -H 'Origin: {origin}' '{url}' -I | grep -i 'access-control'"
                    ),
                    "detail": "Arbitrary origin reflected without credentials",
                })

    # ── HTTP helper ───────────────────────────────────────────────────────────

    def _fetch(self, url: str, extra_headers: dict = None) -> Optional[dict]:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; EVHunter/3.0)",
                "Accept":     "text/html,*/*",
            }
            if extra_headers:
                headers.update(extra_headers)

            req = urllib.request.Request(url, headers=headers, method="GET")

            # Don't follow redirects for some tests
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None

            opener = urllib.request.build_opener(NoRedirectHandler)
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    body = resp.read(50_000).decode("utf-8", errors="replace")
                    resp_headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                    return {
                        "status":   resp.status,
                        "body":     body,
                        "length":   len(body),
                        "headers":  resp_headers,
                        "acao":     resp_headers.get("access-control-allow-origin", ""),
                        "acac":     resp_headers.get("access-control-allow-credentials", ""),
                        "location": resp_headers.get("location", ""),
                    }
            except urllib.error.HTTPError as e:
                err_headers = {k.lower(): v for k, v in dict(e.headers).items()}
                body = e.read(1000).decode("utf-8", errors="replace") if e.fp else ""
                return {
                    "status":   e.code,
                    "body":     body,
                    "length":   len(body),
                    "headers":  err_headers,
                    "acao":     err_headers.get("access-control-allow-origin", ""),
                    "acac":     err_headers.get("access-control-allow-credentials", ""),
                    "location": err_headers.get("location", ""),
                }
        except Exception:
            return None

    # ── Display ───────────────────────────────────────────────────────────────

    def _print_table(self, result: dict):
        vulns = result["vulnerabilities"]
        if not vulns:
            console.print("  [dim]  No header injection vulnerabilities found[/dim]")
            return

        tbl = Table(
            title=f"  [bold red]⚡ Header Injection ({len(vulns)})[/bold red]",
            box=box.SIMPLE_HEAVY, header_style="bold cyan", border_style="bright_red",
        )
        tbl.add_column("Severity", width=10)
        tbl.add_column("Type",     max_width=30)
        tbl.add_column("Header",   max_width=25, style="cyan")
        tbl.add_column("URL",      max_width=40, style="dim")
        SEV = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        for v in vulns:
            sev = v.get("severity", "medium")
            tbl.add_row(
                f"[{SEV.get(sev,'white')}]{sev.upper()}[/{SEV.get(sev,'white')}]",
                v.get("type", "?")[:30],
                v.get("header", "?")[:25],
                v.get("url", "?")[:40],
            )
        console.print(tbl)
