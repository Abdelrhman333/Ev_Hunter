"""
EVHunter — CORS Misconfiguration Checker
Tests for:
  - Wildcard origin (*)
  - Null origin reflection
  - Arbitrary origin reflection
  - Credentials + wildcard (dangerous combo)
  - Subdomain origin reflection
  - Pre-domain bypass (evil.target.com)
"""

import urllib.error
import urllib.request
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

TEST_ORIGINS = [
    ("Arbitrary domain",    "https://evil.com"),
    ("Null origin",         "null"),
    ("Subdomain prefix",    "https://eviltarget.com"),
    ("Subdomain of target", None),      # filled in at runtime: evil.{target}
    ("HTTP downgrade",      None),      # filled in at runtime: http://{target}
]


class CORSCheckerModule(ScannerModule):
    name        = "cors"
    description = "CORS misconfiguration testing across multiple bypass techniques"

    def run(self, target: str, urls: list[str] = None, **kwargs) -> dict[str, Any]:
        self._start_timer()
        self._status(f"CORS testing on [cyan]{target}[/cyan]…")

        # Build base domain
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        result: dict[str, Any] = {
            "ok":       True,
            "target":   target,
            "findings": [],
            "summary":  "",
        }

        # Use provided URLs or derive from target
        test_urls = urls or [
            f"https://{domain}",
            f"http://{domain}",
        ]

        # Build dynamic origins
        origins = [
            ("Arbitrary domain",    "https://evil.com"),
            ("Null origin",         "null"),
            ("Subdomain of target", f"https://evil.{domain}"),
            ("Prefix domain",       f"https://evil{domain}"),
            ("HTTP downgrade",      f"http://{domain}"),
        ]

        for url in test_urls[:5]:  # cap
            for origin_label, origin in origins:
                finding = self._test_cors(url, origin, origin_label, domain)
                if finding:
                    result["findings"].append(finding)

        if result["findings"]:
            result["summary"] = (
                f"Found {len(result['findings'])} CORS misconfiguration(s) — "
                "potential for cross-origin data theft"
            )
        else:
            result["summary"] = "No CORS misconfigurations detected"

        self._ok(f"CORS done — {len(result['findings'])} issue(s) [{self._elapsed()}]")
        self._print_table(result)
        return result

    # ── Core tester ───────────────────────────────────────────────────────────

    def _test_cors(self, url: str, origin: str, label: str, domain: str) -> dict | None:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Origin":      origin,
                    "User-Agent":  "EVHunter/2.0",
                    "Accept":      "*/*",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = {k.lower(): v for k, v in dict(resp.headers).items()}
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in dict(e.headers).items()}
        except Exception:
            return None

        acao  = headers.get("access-control-allow-origin", "")
        acac  = headers.get("access-control-allow-credentials", "").lower()
        acam  = headers.get("access-control-allow-methods", "")

        if not acao:
            return None  # No CORS headers at all

        vuln    = False
        detail  = ""
        severity = "info"

        if acao == "*":
            if acac == "true":
                # This is actually invalid per spec but some servers do it
                vuln     = True
                severity = "high"
                detail   = "Wildcard origin (*) with Allow-Credentials: true — browser ignores this but server is misconfigured"
            else:
                vuln     = True
                severity = "low"
                detail   = "Wildcard origin (*) allows any domain to read public responses"

        elif acao == origin and origin != "null":
            # Reflected an arbitrary/attacker origin
            if acac == "true":
                vuln     = True
                severity = "critical"
                detail   = (
                    f"Origin '{origin}' ({label}) is fully reflected with "
                    f"Allow-Credentials: true — attacker can steal authenticated responses!"
                )
            elif origin not in (f"https://{domain}", f"http://{domain}"):
                vuln     = True
                severity = "high"
                detail   = f"Origin '{origin}' ({label}) is reflected — cross-origin reads possible"

        elif acao == "null" and origin == "null":
            if acac == "true":
                vuln     = True
                severity = "high"
                detail   = "Null origin reflected with Allow-Credentials: true — sandbox iframe attack possible"

        if not vuln:
            return None

        return {
            "url":      url,
            "origin":   origin,
            "label":    label,
            "acao":     acao,
            "acac":     acac,
            "acam":     acam,
            "severity": severity,
            "detail":   detail,
        }

    def _print_table(self, result: dict):
        if not result["findings"]:
            console.print("  [dim]  No CORS issues found[/dim]")
            return
        tbl = Table(
            title="  [bold]CORS Findings[/bold]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            border_style="bright_red",
        )
        tbl.add_column("URL",      max_width=35, style="dim")
        tbl.add_column("Test",     max_width=20)
        tbl.add_column("ACAO",     max_width=25)
        tbl.add_column("Creds",    width=6)
        tbl.add_column("Severity", width=10)
        SEV = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        for f in result["findings"]:
            sev = f["severity"]
            tbl.add_row(
                f["url"][:35],
                f["label"],
                f["acao"][:25],
                f["acac"] or "false",
                f"[{SEV.get(sev,'white')}]{sev.upper()}[/{SEV.get(sev,'white')}]",
            )
        console.print(tbl)
        if result["summary"]:
            console.print(f"  [yellow]  {result['summary']}[/yellow]")
