"""
BugHunter - Configuration Manager
Handles first-run setup and persistent config via ~/.bughunter/config.json
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box

console = Console()

CONFIG_DIR  = Path.home() / ".bughunter"
CONFIG_FILE = CONFIG_DIR / "config.json"
DB_FILE     = CONFIG_DIR / "findings.db"
REPORTS_DIR = CONFIG_DIR / "reports"

REQUIRED_KEYS = ["ai_api_key", "ai_api_url", "ai_model", "osintcat_api_key"]


def _banner():
    art = Text()
    art.append("  ██████╗ ██╗   ██╗ ██████╗ \n", style="bold red")
    art.append("  ██╔══██╗██║   ██║██╔════╝ \n", style="bold red")
    art.append("  ██████╔╝██║   ██║██║  ███╗\n", style="bold yellow")
    art.append("  ██╔══██╗██║   ██║██║   ██║\n", style="bold yellow")
    art.append("  ██████╔╝╚██████╔╝╚██████╔╝\n", style="bold green")
    art.append("  ╚═════╝  ╚═════╝  ╚═════╝ \n", style="bold green")
    art.append("\n  AI-Augmented Bug Hunter Framework", style="bold cyan")
    art.append("\n  v1.0 — Low-Token Edition", style="dim")
    console.print(Panel(art, border_style="bright_blue", box=box.DOUBLE_EDGE, padding=(1, 4)))


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def is_configured() -> bool:
    cfg = load_config()
    return all(cfg.get(k) for k in REQUIRED_KEYS)


def run_setup(force: bool = False):
    """Interactive first-run configuration wizard."""
    _banner()

    cfg = load_config() if not force else {}

    console.print(Panel(
        "[bold yellow]⚙  First-Time Configuration Wizard[/bold yellow]\n"
        "[dim]Settings are saved to ~/.bughunter/config.json[/dim]",
        border_style="yellow"
    ))

    console.print()

    # ── AI Provider ──────────────────────────────────────────────────────────
    console.print("[bold cyan]▸ AI Provider[/bold cyan]")
    cfg["ai_api_url"] = Prompt.ask(
        "  API Base URL",
        default=cfg.get("ai_api_url", "https://api.openai.com/v1"),
        console=console
    )
    cfg["ai_api_key"] = Prompt.ask(
        "  API Key",
        default=cfg.get("ai_api_key", ""),
        password=True,
        console=console
    )
    cfg["ai_model"] = Prompt.ask(
        "  Model Name",
        default=cfg.get("ai_model", "gpt-4o-mini"),
        console=console
    )

    console.print()

    # ── OSINTCat ─────────────────────────────────────────────────────────────
    console.print("[bold cyan]▸ OSINTCat Breach API[/bold cyan]")
    console.print("  [dim]Get your key at https://www.osintcat.net[/dim]")
    cfg["osintcat_api_key"] = Prompt.ask(
        "  OSINTCat API Key",
        default=cfg.get("osintcat_api_key", ""),
        password=True,
        console=console
    )

    console.print()

    # ── Scan Defaults ─────────────────────────────────────────────────────────
    console.print("[bold cyan]▸ Scan Defaults[/bold cyan]")
    cfg["rate_limit"]   = int(Prompt.ask("  Requests per second (rate limit)", default=str(cfg.get("rate_limit", 10)), console=console))
    cfg["concurrency"]  = int(Prompt.ask("  Max concurrent tasks",             default=str(cfg.get("concurrency", 20)), console=console))
    cfg["scope_strict"] = Confirm.ask("  Strict scope enforcement?",           default=cfg.get("scope_strict", True), console=console)

    console.print()

    # ── Legal ─────────────────────────────────────────────────────────────────
    console.print(Panel(
        "[bold red]⚠  LEGAL NOTICE[/bold red]\n\n"
        "This tool is for [bold]authorized security testing only[/bold].\n"
        "Unauthorized use may violate computer fraud laws.\n"
        "You are solely responsible for your actions.",
        border_style="red"
    ))
    agreed = Confirm.ask("  I confirm I will only scan systems I am authorized to test", default=False, console=console)
    if not agreed:
        console.print("[bold red]  Aborted. You must agree to the terms to use BugHunter.[/bold red]")
        sys.exit(1)

    cfg["legal_agreed"] = True

    save_config(cfg)
    console.print("\n[bold green]  ✔ Configuration saved to ~/.bughunter/config.json[/bold green]\n")
    return cfg


def get_config() -> dict:
    """Load config, running setup if missing."""
    if not is_configured():
        return run_setup()
    return load_config()
