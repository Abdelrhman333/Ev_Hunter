"""
EVHunter — Secret / Credential Scanner
Scans HTTP response bodies for exposed secrets:
  AWS keys, GitHub tokens, JWT, API keys, private keys,
  passwords in JS, connection strings, GCP/Azure creds, etc.
"""

import re
import urllib.error
import urllib.request
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

# ── Secret patterns ───────────────────────────────────────────────────────────
# (name, regex, severity, context_chars)

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # Cloud providers
    ("AWS Access Key",      r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",   "critical"),
    ("AWS Secret Key",      r"(?i)aws.{0,20}secret.{0,10}[=:]\s*['\"]?([A-Za-z0-9/+]{40})",    "critical"),
    ("GCP API Key",         r"AIza[0-9A-Za-z\-_]{35}",                                          "critical"),
    ("GCP Service Account", r'"type"\s*:\s*"service_account"',                                  "critical"),
    ("Azure SAS Token",     r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=",                                   "high"),
    ("Azure AD Secret",     r"(?i)azure.{0,20}(secret|key).{0,10}[=:]\s*['\"]?[A-Za-z0-9]{32,}","high"),
    # Version control
    ("GitHub PAT",          r"(ghp|ghs|gho|ghu|github_pat)_[A-Za-z0-9_]{36,}",                "critical"),
    ("GitLab Token",        r"glpat-[A-Za-z0-9\-_]{20}",                                       "critical"),
    # Tokens
    ("JWT Token",           r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "high"),
    ("Slack Bot Token",     r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}",                       "high"),
    ("Slack Webhook",       r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}", "high"),
    ("Stripe Live Key",     r"sk_live_[0-9a-zA-Z]{24,}",                                        "critical"),
    ("Stripe Test Key",     r"sk_test_[0-9a-zA-Z]{24,}",                                        "medium"),
    ("Twilio Account SID",  r"AC[a-z0-9]{32}",                                                  "medium"),
    ("SendGrid Key",        r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",                    "high"),
    ("Mailchimp Key",       r"[0-9a-f]{32}-us[0-9]{1,2}",                                       "medium"),
    # Crypto / PKI
    ("Private Key",         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",            "critical"),
    ("PGP Private Key",     r"-----BEGIN PGP PRIVATE KEY BLOCK-----",                           "critical"),
    # Generic secrets
    ("High-Entropy Secret", r"(?i)(secret|password|passwd|token|api_key|apikey|auth)\s*[=:]\s*['\"]([A-Za-z0-9/+_\-]{20,})['\"]", "high"),
    ("Connection String",   r"(?i)(mongodb|postgresql|mysql|redis)://[^@\s]+:[^@\s]+@",         "critical"),
    ("Basic Auth in URL",   r"https?://[^@\s]+:[^@\s]+@",                                       "high"),
    # Firebase / Heroku
    ("Firebase URL",        r"[a-z0-9-]+\.firebaseio\.com",                                     "medium"),
    ("Heroku API Key",      r"(?i)heroku.{0,20}['\"]([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})['\"]", "high"),
]

FALSE_POSITIVE_WORDS = {
    "example", "placeholder", "your_key_here", "xxx", "yyy", "zzz",
    "your-api-key", "insert-key", "dummy", "test123", "password123",
    "changeme", "replace_me", "todo", "fixme",
}


class SecretScannerModule(ScannerModule):
    name        = "secret"
    description = "Secret/credential detection in HTTP responses and JS files"

    def run(self, target: str, urls: list[str] = None, **kwargs) -> dict[str, Any]:
        self._start_timer()
        self._status(f"Secret scanning on [cyan]{target}[/cyan]…")

        test_urls = urls or [
            target if target.startswith("http") else f"https://{target}",
        ]

        result: dict[str, Any] = {
            "ok":      True,
            "target":  target,
            "secrets": [],
        }

        for url in test_urls[:20]:
            body = self._fetch(url)
            if body:
                found = self._scan(body, url)
                result["secrets"].extend(found)

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict] = []
        for s in result["secrets"]:
            key = f"{s['type']}:{s['match'][:20]}"
            if key not in seen:
                seen.add(key)
                unique.append(s)
        result["secrets"] = unique

        self._ok(
            f"Secret scan done — [bold {'red' if unique else 'green'}]{len(unique)}[/bold {'red' if unique else 'green'}]"
            f" secret(s) found [{self._elapsed()}]"
        )
        if unique:
            self._print_table(result)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> str | None:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "EVHunter/2.0", "Accept": "*/*"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                ct = resp.headers.get("Content-Type", "")
                # Skip binary content
                if any(x in ct for x in ("image", "video", "font", "pdf")):
                    return None
                return resp.read(512_000).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _scan(self, content: str, url: str) -> list[dict]:
        findings: list[dict] = []
        for name, pattern, severity in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                match_text = m.group(0)
                # Skip obvious false positives
                if any(fp in match_text.lower() for fp in FALSE_POSITIVE_WORDS):
                    continue
                # Get context (50 chars around match)
                start   = max(0, m.start() - 40)
                end     = min(len(content), m.end() + 40)
                context = content[start:end].replace("\n", " ").strip()
                findings.append({
                    "type":     name,
                    "match":    match_text[:80],
                    "context":  context[:150],
                    "url":      url,
                    "severity": severity,
                })
        return findings

    def _print_table(self, result: dict):
        tbl = Table(
            title=f"  [bold red]⚠ Secrets Found ({len(result['secrets'])})[/bold red]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            border_style="bright_red",
        )
        tbl.add_column("Type",     max_width=28)
        tbl.add_column("Match",    max_width=30, style="red")
        tbl.add_column("Severity", width=10)
        tbl.add_column("URL",      max_width=35, style="dim")
        SEV = {"critical": "bold red", "high": "red", "medium": "yellow"}
        for s in result["secrets"][:20]:
            sev = s["severity"]
            tbl.add_row(
                s["type"],
                s["match"][:30] + ("…" if len(s["match"]) > 30 else ""),
                f"[{SEV.get(sev,'white')}]{sev.upper()}[/{SEV.get(sev,'white')}]",
                s["url"][:35],
            )
        console.print(tbl)
