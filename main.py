#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║          BugHunter — AI-Augmented Bug Hunter         ║
║           Low-Token Edition  |  v1.0                ║
╚══════════════════════════════════════════════════════╝

Usage:
  python main.py configure          # First-time setup
  python main.py recon <target>     # Full recon pipeline
  python main.py history            # View past scans
  python main.py report <scan_id>   # Regenerate a report
"""

import sys
import time
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    import rich
    import typer
except ImportError:
    print("[!] Missing dependencies. Run: pip install rich typer")
    sys.exit(1)

import typer
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

# ── Local imports ─────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from config import get_config, run_setup, CONFIG_DIR, DB_FILE, REPORTS_DIR
from ai_client import AIClient, SEV_COLORS
from db import Database
from modules.recon import (
    run_nmap, enumerate_subdomains, probe_alive, run_nuclei,
    check_breach, verify_with_curl, print_alive_table, print_findings_table
)
from modules.reporting import save_report

# ── App setup ─────────────────────────────────────────────────────────────────
app     = typer.Typer(add_completion=False, rich_markup_mode="rich", no_args_is_help=True)
console = Console()

BANNER = """
    ███████╗██╗   ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗     
    ██╔════╝██║   ██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗    
    █████╗  ██║   ██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝    
    ██╔══╝  ╚██╗ ██╔╝    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗    
    ███████╗ ╚████╔╝     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║    
    ╚══════╝  ╚═══╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝    
                                                                             
"""


def _print_banner():
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        "  [dim]AI-Augmented Bug Hunter Framework  |  v1.0  |  Low-Token Edition[/dim]\n"
    )


def _section(title: str):
    console.print()
    console.print(Rule(f"[bold cyan]  {title}  [/bold cyan]", style="bright_blue"))
    console.print()


def _severity_panel(findings: list[dict]):
    """Print a compact severity summary box."""
    from collections import Counter
    counts = Counter((f.get("severity") or "info").lower() for f in findings)
    parts  = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n:
            color = SEV_COLORS.get(sev, "white")
            parts.append(f"[{color}]{sev.upper()}: {n}[/{color}]")

    console.print(Panel(
        "  " + "   ".join(parts) if parts else "[dim]  No findings[/dim]",
        title="[bold]Severity Summary[/bold]",
        border_style="bright_blue",
        padding=(0, 2),
    ))


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def configure():
    """Run the interactive configuration wizard."""
    run_setup(force=True)


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    fast: bool   = typer.Option(True,  "--fast/--deep",    help="Fast nmap (top-100) or deep (top-1000)"),
    nuclei: bool = typer.Option(True,  "--nuclei/--no-nuclei", help="Run nuclei scan"),
    verify: bool = typer.Option(True,  "--verify/--no-verify", help="AI-verify findings with curl"),
    report: bool = typer.Option(True,  "--report/--no-report", help="Generate final report"),
):
    """
    [bold cyan]Full Recon Pipeline[/bold cyan]

    nmap → subdomains → httpx → nuclei → AI analysis → breach check → report
    """
    _print_banner()

    # ── Config & DB ───────────────────────────────────────────────────────────
    cfg = get_config()
    db  = Database(DB_FILE)
    ai  = AIClient(cfg["ai_api_url"], cfg["ai_api_key"], cfg["ai_model"])

    # ── Scope check ───────────────────────────────────────────────────────────
    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Mode:[/bold]   Recon\n"
        f"[bold]AI Model:[/bold] {cfg['ai_model']}",
        border_style="bright_blue",
        title="[bold]Scan Configuration[/bold]",
    ))

    from rich.prompt import Confirm
    if not Confirm.ask(f"\n  [yellow]⚠  Confirm you are authorized to scan [bold]{target}[/bold][/yellow]", default=False):
        console.print("[red]  Aborted.[/red]")
        raise typer.Exit()

    scan_id    = db.new_scan(target, "recon")
    all_findings: list[dict] = []

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 1 — Port Scan (nmap)")
    nmap_result = run_nmap(target, fast=fast)
    db.add_asset(scan_id, target, "ip")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 2 — AI Recon Analysis")
    console.print("  [dim]Sending compact nmap summary to AI…[/dim]")

    # Extract subdomain list for AI (we haven't enumerated yet, use domain)
    recon_ai = ai.analyze_recon(nmap_result, [target])
    if recon_ai:
        ai_findings = recon_ai.get("findings", [])
        console.print(f"  [green]✔ AI identified {len(ai_findings)} potential area(s)[/green]")
        if recon_ai.get("summary"):
            console.print(Panel(
                f"[dim]{recon_ai['summary']}[/dim]",
                title="[bold cyan]AI Recon Summary[/bold cyan]",
                border_style="cyan",
                padding=(0, 2),
            ))
        for finding in ai_findings:
            fid = db.add_finding(
                scan_id,
                title    = finding.get("detail", "Potential issue"),
                severity = finding.get("severity", "info"),
                asset    = target,
                detail   = finding.get("detail", ""),
            )
            all_findings.append({**finding, "id": fid, "asset": target, "curl_poc": ""})
    else:
        console.print("  [yellow]  AI analysis unavailable[/yellow]")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 3 — Subdomain Enumeration")
    subdomains = enumerate_subdomains(target)

    for sd in subdomains:
        db.add_asset(scan_id, sd, "subdomain")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 4 — AI Subdomain Analysis")
    if subdomains:
        sub_ai = ai.analyze_subdomains(subdomains)
        if sub_ai:
            flagged = sub_ai.get("flagged", [])
            if flagged:
                console.print(f"  [yellow]  AI flagged {len(flagged)} sensitive subdomain(s)[/yellow]")
                tbl = Table(box=box.SIMPLE, header_style="bold cyan", show_header=True)
                tbl.add_column("Subdomain", style="white")
                tbl.add_column("Reason",    style="yellow")
                tbl.add_column("Sev",       width=8)
                for item in flagged:
                    sev   = item.get("severity", "low")
                    color = SEV_COLORS.get(sev, "white")
                    tbl.add_row(
                        item.get("subdomain", "?"),
                        item.get("reason", "?"),
                        f"[{color}]{sev}[/{color}]",
                    )
                console.print(tbl)

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 5 — HTTP Probe (alive check)")
    alive_hosts = probe_alive(subdomains + [target], max_workers=cfg.get("concurrency", 20))

    for h in alive_hosts:
        db.add_asset(scan_id, h["url"], "endpoint", alive=True)

    if alive_hosts:
        print_alive_table(alive_hosts)

    alive_urls = [h["url"] for h in alive_hosts]

    # ═══════════════════════════════════════════════════════════════════════════
    if nuclei:
        _section("STEP 6 — Nuclei (low-hanging fruit)")
        nuclei_hits = run_nuclei(alive_urls) if alive_urls else []

        # ── AI vuln analysis ─────────────────────────────────────────────────
        if alive_hosts:
            _section("STEP 7 — AI Vulnerability Analysis")
            console.print("  [dim]Preprocessing and sending compact data to AI…[/dim]")

            for host in alive_hosts[:10]:  # Cap to avoid token explosion
                headers      = host.get("headers", {})
                tech_stack   = []
                server = host.get("server", "")
                if server:
                    tech_stack.append(server)

                vuln_ai = ai.analyze_vulns(
                    target    = host["url"],
                    tech_stack = tech_stack,
                    endpoints  = [host["url"]],
                    nuclei_hits = [h for h in nuclei_hits if host["url"] in h.get("url","")],
                    headers   = headers,
                )

                if vuln_ai and vuln_ai.get("vulns"):
                    for v in vuln_ai["vulns"]:
                        fid = db.add_finding(
                            scan_id,
                            title    = v.get("title", "Unknown"),
                            severity = v.get("severity", "medium"),
                            asset    = host["url"],
                            detail   = v.get("reasoning", ""),
                            curl_poc = v.get("curl_verify", ""),
                        )
                        all_findings.append({
                            **v,
                            "id":    fid,
                            "asset": host["url"],
                            "curl_poc": v.get("curl_verify", ""),
                        })
                        console.print(
                            f"  [{'red' if v.get('severity','').lower() in ('critical','high') else 'yellow'}]"
                            f"  ⚡ {v.get('severity','?').upper()}  [/{'red' if v.get('severity','').lower() in ('critical','high') else 'yellow'}]"
                            f"{v.get('title','?')} [{host['url']}]"
                        )

            # Add nuclei findings that weren't covered
            for hit in nuclei_hits:
                fid = db.add_finding(
                    scan_id,
                    title    = f"[nuclei] {hit.get('name', hit.get('template','?'))}",
                    severity = hit.get("severity", "medium"),
                    asset    = hit.get("url", "?"),
                    detail   = f"Template: {hit.get('template','')}",
                    curl_poc = "",
                )
                all_findings.append({
                    "id":       fid,
                    "title":    f"[nuclei] {hit.get('name', hit.get('template','?'))}",
                    "severity": hit.get("severity", "medium"),
                    "asset":    hit.get("url", "?"),
                    "detail":   f"Template: {hit.get('template','')}",
                    "curl_poc": "",
                })
    else:
        nuclei_hits = []

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 8 — Breach Intelligence (OSINTCat)")
    breach_data = check_breach(target, cfg.get("osintcat_api_key", ""))
    if breach_data:
        console.print(Panel(
            f"[yellow]{json.dumps(breach_data, indent=2)[:500]}[/yellow]",
            title="[bold red]Breach Data Found[/bold red]",
            border_style="red",
        ))

    # ═══════════════════════════════════════════════════════════════════════════
    if verify and all_findings:
        _section("STEP 9 — Vulnerability Verification")
        for f in all_findings:
            curl_cmd = f.get("curl_poc", "")
            if not curl_cmd or not curl_cmd.strip().startswith("curl"):
                continue

            console.print(f"  [dim]  Verifying: {f.get('title','?')}…[/dim]")
            status, body, ms = verify_with_curl(curl_cmd)

            verify_ai = ai.verify_finding(
                vuln_title       = f.get("title", "?"),
                curl_response    = body,
                status_code      = status,
                response_time_ms = ms,
            )

            if verify_ai and verify_ai.get("confirmed"):
                f["confirmed"] = True
                console.print(f"  [bold green]  ✔ CONFIRMED: {f.get('title','?')}[/bold green]")
                console.print(f"  [dim]  Evidence: {verify_ai.get('evidence','?')[:120]}[/dim]")

                # Write report section
                rep = ai.write_report({**f, "evidence": verify_ai.get("evidence","")})
                db.confirm_finding(f["id"], report=rep)
                f["report"] = rep
            else:
                reason = (verify_ai or {}).get("false_positive_reason", "")
                console.print(f"  [dim]  Unconfirmed: {f.get('title','?')} — {reason[:80]}[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("SCAN COMPLETE")

    all_findings = db.get_findings(scan_id)
    _severity_panel(all_findings)
    print_findings_table(all_findings, title=f"All Findings — {target}")

    # ── Report ────────────────────────────────────────────────────────────────
    if report:
        _section("STEP 10 — Report Generation")
        import json
        save_report(
            target         = target,
            findings       = all_findings,
            reports_dir    = REPORTS_DIR,
            breach_data    = breach_data,
            alive_count    = len(alive_hosts),
            subdomain_count = len(subdomains),
        )

    db.finish_scan(scan_id)
    console.print(f"\n  [bold green]✔ Scan #{scan_id} finished.[/bold green]")
    db.close()


# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def history():
    """[bold cyan]Show past scans from the database.[/bold cyan]"""
    _print_banner()
    db     = Database(DB_FILE)
    scans  = db.list_scans()
    db.close()

    if not scans:
        console.print("  [dim]No scans recorded yet. Run: bughunter recon <target>[/dim]")
        return

    tbl = Table(
        title="[bold]Scan History[/bold]",
        box=box.SIMPLE_HEAVY,
        border_style="bright_blue",
        header_style="bold cyan",
    )
    tbl.add_column("ID",       width=5,  justify="right")
    tbl.add_column("Target",   max_width=35)
    tbl.add_column("Mode",     width=10)
    tbl.add_column("Status",   width=10)
    tbl.add_column("Findings", width=10, justify="center")
    tbl.add_column("Date",     width=20)

    for s in scans:
        status_style = "green" if s["status"] == "done" else "yellow"
        tbl.add_row(
            str(s["id"]),
            s["target"],
            s["mode"],
            f"[{status_style}]{s['status']}[/{status_style}]",
            str(s.get("findings_count", 0)),
            time.strftime("%Y-%m-%d %H:%M", time.localtime(s["started"])),
        )

    console.print(tbl)


@app.command()
def report(
    scan_id: int = typer.Argument(..., help="Scan ID from history"),
):
    """[bold cyan]Re-generate a report for a past scan.[/bold cyan]"""
    _print_banner()
    db       = Database(DB_FILE)
    findings = db.get_findings(scan_id)

    scans = [s for s in db.list_scans() if s["id"] == scan_id]
    if not scans:
        console.print(f"[red]  Scan #{scan_id} not found.[/red]")
        db.close()
        raise typer.Exit()

    target = scans[0]["target"]
    db.close()

    _section(f"Regenerating report for scan #{scan_id} — {target}")
    save_report(target, findings, REPORTS_DIR)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # First-run check
    from config import is_configured
    skip_args = {"configure", "--help", "-h", "--version"}
    needs_check = len(sys.argv) > 1 and not any(a in skip_args for a in sys.argv[1:])
    if needs_check and not is_configured():
        console.print(Panel(
            "[bold yellow]⚙  First run detected.[/bold yellow]\n\n"
            "Run [bold cyan]python main.py configure[/bold cyan] to set up BugHunter.",
            border_style="yellow",
        ))
        sys.exit(1)

    import json
    app()
