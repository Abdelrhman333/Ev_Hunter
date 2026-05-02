"""
EVHunter - Configuration Manager
Handles first-run setup and persistent config via ~/.evhunter/config.json

Fixes vs original:
  - URL format validation
  - Schema versioning for future migrations
  - Proxy support
  - Scope allow/deny lists
  - Timeout tuning
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.text import Text
from rich import box

console = Console()

CONFIG_DIR  = Path.home() / ".evhunter"
CONFIG_FILE = CONFIG_DIR / "config.json"
DB_FILE     = CONFIG_DIR / "findings.db"
REPORTS_DIR = CONFIG_DIR / "reports"
LOGS_DIR    = CONFIG_DIR / "logs"

CONFIG_VERSION = 2
REQUIRED_KEYS  = ["ai_api_key", "ai_api_url", "ai_model"]


# ─────────────────────────────────────────────────────────────────────────────

def _banner():
    art = Text()
    art.append("  ███████╗██╗   ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗\n",  style="bold red")
    art.append("  ██╔════╝██║   ██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n", style="bold red")
    art.append("  █████╗  ██║   ██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n", style="bold red")
    art.append("  ██╔══╝  ╚██╗ ██╔╝    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n", style="bold red")
    art.append("  ███████╗ ╚████╔╝     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n", style="bold red")
    art.append("  ╚══════╝  ╚═══╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n", style="bold red")
    art.append("\n  AI-Augmented Bug Hunter Framework  |  v2.0", style="bold cyan")
    art.append("\n  Multi-Module Edition — DNS · SSL · WAF · CORS · Secrets · JS", style="dim")
    console.print(Panel(art, border_style="bright_blue", box=box.DOUBLE_EDGE, padding=(1, 2)))


def _validate_url(url: str) -> bool:
    return bool(re.match(r"^https?://", url.strip()))


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    cfg["_version"] = CONFIG_VERSION
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def is_configured() -> bool:
    cfg = load_config()
    return all(cfg.get(k) for k in REQUIRED_KEYS)


def _migrate(cfg: dict) -> dict:
    """Migrate config to current version if needed."""
    ver = cfg.get("_version", 1)
    if ver < 2:
        # v1 → v2: rename bughunter keys, add new defaults
        cfg.setdefault("osintcat_api_key", "")
        cfg.setdefault("wayback_enabled", True)
        cfg.setdefault("dns_enabled", True)
        cfg.setdefault("ssl_enabled", True)
        cfg.setdefault("cors_enabled", True)
        cfg.setdefault("secret_scan_enabled", True)
        cfg.setdefault("js_scan_enabled", True)
        cfg.setdefault("waf_detect_enabled", True)
        cfg["_version"] = 2
        save_config(cfg)
    return cfg


def run_setup(force: bool = False):
    """Interactive first-run configuration wizard."""
    _banner()
    cfg = load_config() if not force else {}

    console.print(Panel(
        "[bold yellow]⚙  Configuration Wizard[/bold yellow]\n"
        "[dim]Settings saved to ~/.evhunter/config.json[/dim]",
        border_style="yellow"
    ))

    # ── AI Provider ──────────────────────────────────────────────────────────
    console.print("\n[bold cyan]▸ AI Provider[/bold cyan]")
    while True:
        url = Prompt.ask(
            "  API Base URL",
            default=cfg.get("ai_api_url", "https://api.openai.com/v1"),
        )
        if _validate_url(url):
            cfg["ai_api_url"] = url.rstrip("/")
            break
        console.print("  [red]  URL must start with http:// or https://[/red]")

    cfg["ai_api_key"] = Prompt.ask("  API Key", default=cfg.get("ai_api_key", ""), password=True)
    cfg["ai_model"]   = Prompt.ask("  Model Name", default=cfg.get("ai_model", "gpt-4o-mini"))

    # ── OSINTCat ─────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]▸ OSINTCat Breach API (optional)[/bold cyan]")
    console.print("  [dim]Get your key at https://www.osintcat.net — leave blank to skip[/dim]")
    cfg["osintcat_api_key"] = Prompt.ask(
        "  OSINTCat API Key", default=cfg.get("osintcat_api_key", ""), password=True
    )

    # ── Proxy (optional) ─────────────────────────────────────────────────────
    console.print("\n[bold cyan]▸ Proxy (optional)[/bold cyan]")
    proxy = Prompt.ask(
        "  HTTP Proxy (e.g. http://127.0.0.1:8080, blank to skip)",
        default=cfg.get("proxy", ""),
    )
    cfg["proxy"] = proxy if proxy and _validate_url(proxy) else ""

    # ── Module toggles ────────────────────────────────────────────────────────
    console.print("\n[bold cyan]▸ Modules to Enable[/bold cyan]")
    for mod, label in [
        ("dns_enabled",        "DNS Enumeration (A, MX, TXT, NS, zone-xfer)"),
        ("ssl_enabled",        "SSL/TLS Certificate Analysis"),
        ("waf_detect_enabled", "WAF / CDN Detection"),
        ("cors_enabled",       "CORS Misconfiguration Testing"),
        ("secret_scan_enabled","Secret / Token Scanner in HTTP Responses"),
        ("js_scan_enabled",    "JavaScript Endpoint Extraction"),
        ("wayback_enabled",    "Wayback Machine Historical Endpoints"),
    ]:
        cfg[mod] = Confirm.ask(f"  Enable {label}?", default=cfg.get(mod, True))

    # ── Scan Defaults ─────────────────────────────────────────────────────────
    console.print("\n[bold cyan]▸ Scan Defaults[/bold cyan]")
    cfg["rate_limit"]  = int(Prompt.ask("  Requests/second (rate limit)", default=str(cfg.get("rate_limit", 10))))
    cfg["concurrency"] = int(Prompt.ask("  Max concurrent tasks",         default=str(cfg.get("concurrency", 20))))
    cfg["timeout"]     = int(Prompt.ask("  Request timeout (seconds)",    default=str(cfg.get("timeout", 10))))

    # ── Legal ─────────────────────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        "[bold red]⚠  LEGAL NOTICE[/bold red]\n\n"
        "This tool is for [bold]authorized security testing only[/bold].\n"
        "Unauthorized use may violate computer fraud and abuse laws.\n"
        "You are solely responsible for every action taken with this tool.",
        border_style="red"
    ))
    if not Confirm.ask("  I confirm I will only scan systems I am authorized to test", default=False):
        console.print("[bold red]  Aborted.[/bold red]")
        sys.exit(1)

    cfg["legal_agreed"] = True
    save_config(cfg)
    console.print("\n[bold green]  ✔ Configuration saved to ~/.evhunter/config.json[/bold green]\n")
    return cfg


def get_config() -> dict:
    """Load config, running setup if missing. Migrates old versions."""
    if not is_configured():
        return run_setup()
    cfg = load_config()
    return _migrate(cfg)
