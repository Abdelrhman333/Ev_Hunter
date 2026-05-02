#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║          EVHunter — AI-Augmented Bug Hunter          ║
║           Multi-Module Edition  |  v2.1             ║
╚══════════════════════════════════════════════════════╝

Usage:
  python main.py configure          # First-time setup
  python main.py recon <target>     # Full recon pipeline
  python main.py history            # View past scans
  python main.py report <scan_id>   # Regenerate a report

Fixes v2.1:
  - All 7 scanner modules are now wired into the recon pipeline
  - scan_notes populated and passed to reporting
  - Removed duplicate json import inside recon()
  - Module toggles respect config flags
"""

import json
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
from rich.prompt import Confirm
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
    check_breach, verify_with_curl, print_alive_table, print_findings_table,
)
from modules.reporting import save_report

# ── Scanner modules ───────────────────────────────────────────────────────────
from modules.dns_enum      import DNSEnumModule
from modules.ssl_analyzer  import SSLAnalyzerModule
from modules.waf_detect    import WAFDetectModule
from modules.tech_detect   import TechDetectModule
from modules.js_analyzer   import JSAnalyzerModule
from modules.secret_scanner import SecretScannerModule
from modules.cors_checker  import CORSCheckerModule

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
        "  [dim]AI-Augmented Bug Hunter Framework  |  v1.0  "
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



@app.command()
def configure():
    """Run the interactive configuration wizard."""
    run_setup(force=True)


@app.command()
def recon(
    target:  str  = typer.Argument(..., help="Target domain, e.g. example.com"),
    fast:    bool = typer.Option(True,  "--fast/--deep",       help="Fast nmap (top-100) or deep (top-1000)"),
    nuclei:  bool = typer.Option(True,  "--nuclei/--no-nuclei",help="Run nuclei scan"),
    verify:  bool = typer.Option(True,  "--verify/--no-verify",help="AI-verify findings with curl"),
    report:  bool = typer.Option(True,  "--report/--no-report",help="Generate final report"),
):
    """
    [bold cyan]Full Recon Pipeline[/bold cyan]

    nmap → subdomains → DNS → httpx → WAF → tech → SSL → nuclei → AI analysis
    → JS → secrets → CORS → breach check → verification → report
    """
    _print_banner()

    # ── Config & DB ───────────────────────────────────────────────────────────
    cfg = get_config()
    db  = Database(DB_FILE)
    ai  = AIClient(cfg["ai_api_url"], cfg["ai_api_key"], cfg["ai_model"])

    timeout     = cfg.get("timeout", 10)
    proxy       = cfg.get("proxy", "")
    concurrency = cfg.get("concurrency", 20)

    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Mode:[/bold]   Recon\n"
        f"[bold]AI Model:[/bold] {cfg['ai_model']}",
        border_style="bright_blue",
        title="[bold]Scan Configuration[/bold]",
    ))

    if not Confirm.ask(
        f"\n  [yellow]⚠  Confirm you are authorized to scan [bold]{target}[/bold][/yellow]",
        default=False,
    ):
        console.print("[red]  Aborted.[/red]")
        raise typer.Exit()

    scan_id       = db.new_scan(target, "recon")
    all_findings: list[dict] = []
    scan_notes:   dict       = {}         

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 1 — Port Scan (nmap)")
    nmap_result = run_nmap(target, fast=fast)
    db.add_asset(scan_id, target, "ip")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 2 — AI Recon Analysis")
    console.print("  [dim]Sending compact nmap summary to AI…[/dim]")

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
    subdomains = enumerate_subdomains(target, use_wayback=cfg.get("wayback_enabled", True))

    for sd in subdomains:
        db.add_asset(scan_id, sd, "subdomain")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 4 — DNS Enumeration")
    if cfg.get("dns_enabled", True):
        dns_mod    = DNSEnumModule(timeout=timeout, proxy=proxy)
        dns_result = dns_mod.run(target)
        scan_notes["dns"] = dns_result

        # Persist DNS issues as findings
        for issue in dns_result.get("issues", []):
            fid = db.add_finding(
                scan_id,
                title    = issue.get("type", "DNS Issue"),
                severity = issue.get("severity", "medium"),
                asset    = target,
                detail   = issue.get("detail", ""),
                module   = "dns",
            )
            all_findings.append({
                "id": fid, "title": issue.get("type", "DNS Issue"),
                "severity": issue.get("severity", "medium"),
                "asset": target, "detail": issue.get("detail", ""),
                "module": "dns", "curl_poc": "",
            })

        # AI analysis of DNS data
        if dns_result.get("records"):
            dns_ai = ai.analyze_dns({
                "records":  dns_result.get("records", {}),
                "security": dns_result.get("security", {}),
                "issues":   dns_result.get("issues", []),
            })
            if dns_ai and dns_ai.get("issues"):
                console.print(f"  [yellow]  AI flagged {len(dns_ai['issues'])} DNS issue(s)[/yellow]")
    else:
        console.print("  [dim]  DNS enumeration disabled in config[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 5 — AI Subdomain Analysis")
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
    _section("STEP 6 — HTTP Probe (alive check)")
    alive_hosts = probe_alive(subdomains + [target], max_workers=concurrency)

    for h in alive_hosts:
        db.add_asset(scan_id, h["url"], "endpoint", alive=True)

    if alive_hosts:
        print_alive_table(alive_hosts)

    alive_urls = [h["url"] for h in alive_hosts]

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 7 — WAF / CDN Detection")
    if cfg.get("waf_detect_enabled", True):
        waf_mod    = WAFDetectModule(timeout=timeout, proxy=proxy)
        waf_result = waf_mod.run(target)
        scan_notes["waf"] = waf_result
        if waf_result.get("detected"):
            names = ", ".join(d["name"] for d in waf_result["detected"])
            console.print(f"  [cyan]  ℹ Detected: {names}[/cyan]")
    else:
        console.print("  [dim]  WAF detection disabled in config[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 8 — Technology Detection")
    tech_mod    = TechDetectModule(timeout=timeout, proxy=proxy)
    tech_result = tech_mod.run(target, urls=alive_urls[:3])
    scan_notes["tech"] = tech_result

    # Build consolidated tech stack for AI vuln analysis
    tech_stack = [t["name"] for t in tech_result.get("tech", [])]

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 9 — SSL / TLS Analysis")
    if cfg.get("ssl_enabled", True):
        # Strip any scheme for the SSL module
        ssl_host   = target.replace("https://", "").replace("http://", "").split("/")[0]
        ssl_mod    = SSLAnalyzerModule(timeout=timeout, proxy=proxy)
        ssl_result = ssl_mod.run(ssl_host)
        scan_notes["ssl"] = ssl_result

        for issue in ssl_result.get("issues", []):
            fid = db.add_finding(
                scan_id,
                title    = issue.get("type", "SSL Issue"),
                severity = issue.get("severity", "medium"),
                asset    = target,
                detail   = issue.get("detail", ""),
                module   = "ssl",
            )
            all_findings.append({
                "id": fid, "title": issue.get("type", "SSL Issue"),
                "severity": issue.get("severity", "medium"),
                "asset": target, "detail": issue.get("detail", ""),
                "module": "ssl", "curl_poc": "",
            })
    else:
        console.print("  [dim]  SSL analysis disabled in config[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    nuclei_hits: list[dict] = []
    if nuclei:
        _section("STEP 10 — Nuclei (low-hanging fruit)")
        nuclei_hits = run_nuclei(alive_urls) if alive_urls else []

        # ── AI vuln analysis ─────────────────────────────────────────────────
        if alive_hosts:
            _section("STEP 11 — AI Vulnerability Analysis")
            console.print("  [dim]Preprocessing and sending compact data to AI…[/dim]")

            for host in alive_hosts[:10]:
                headers    = host.get("headers", {})
                host_tech  = list(tech_stack)  # already built from tech_detect
                server     = host.get("server", "")
                if server and server not in host_tech:
                    host_tech.append(server)

                vuln_ai = ai.analyze_vulns(
                    target      = host["url"],
                    tech_stack  = host_tech,
                    endpoints   = [host["url"]],
                    nuclei_hits = [h for h in nuclei_hits if host["url"] in h.get("url", "")],
                    headers     = headers,
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
                            "id":      fid,
                            "asset":   host["url"],
                            "curl_poc": v.get("curl_verify", ""),
                        })
                        sev   = v.get("severity", "").lower()
                        color = "red" if sev in ("critical", "high") else "yellow"
                        console.print(
                            f"  [{color}]  ⚡ {sev.upper()}  [/{color}]"
                            f"{v.get('title', '?')} [{host['url']}]"
                        )

            # Add nuclei findings
            for hit in nuclei_hits:
                fid = db.add_finding(
                    scan_id,
                    title    = f"[nuclei] {hit.get('name', hit.get('template', '?'))}",
                    severity = hit.get("severity", "medium"),
                    asset    = hit.get("url", "?"),
                    detail   = f"Template: {hit.get('template', '')}",
                    curl_poc = "",
                    module   = "nuclei",
                )
                all_findings.append({
                    "id":       fid,
                    "title":    f"[nuclei] {hit.get('name', hit.get('template', '?'))}",
                    "severity": hit.get("severity", "medium"),
                    "asset":    hit.get("url", "?"),
                    "detail":   f"Template: {hit.get('template', '')}",
                    "module":   "nuclei",
                    "curl_poc": "",
                })

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 12 — JavaScript Analysis")
    if cfg.get("js_scan_enabled", True):
        js_mod    = JSAnalyzerModule(timeout=timeout, proxy=proxy)
        js_result = js_mod.run(target, alive_hosts=alive_hosts)
        scan_notes["js"] = js_result

        # Surface JS secrets as findings
        for secret in js_result.get("secrets", []):
            fid = db.add_finding(
                scan_id,
                title    = f"[JS] Exposed {secret.get('type', 'Secret')}",
                severity = secret.get("severity", "high"),
                asset    = secret.get("url", target),
                detail   = f"Value (truncated): {secret.get('value', '')[:60]}",
                module   = "js",
            )
            all_findings.append({
                "id": fid, "title": f"[JS] Exposed {secret.get('type', 'Secret')}",
                "severity": secret.get("severity", "high"),
                "asset": secret.get("url", target),
                "detail": f"Value (truncated): {secret.get('value', '')[:60]}",
                "module": "js", "curl_poc": "",
            })

        # Send JS summary to AI for deeper analysis
        if js_result.get("endpoints") or js_result.get("secrets"):
            js_ai = ai.analyze_js({
                "endpoints":    js_result.get("endpoints", [])[:20],
                "secrets":      js_result.get("secrets", [])[:10],
                "s3_buckets":   js_result.get("s3_buckets", []),
                "sourcemaps":   js_result.get("sourcemaps", []),
                "internal_ips": js_result.get("internal_ips", []),
            })
            if js_ai and js_ai.get("summary"):
                console.print(f"  [dim]  AI JS summary: {js_ai['summary'][:120]}[/dim]")
    else:
        console.print("  [dim]  JS analysis disabled in config[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 13 — Secret Scanner")
    if cfg.get("secret_scan_enabled", True):
        secret_mod    = SecretScannerModule(timeout=timeout, proxy=proxy)
        secret_result = secret_mod.run(target, urls=alive_urls[:10])
        scan_notes["secrets"] = secret_result

        for secret in secret_result.get("secrets", []):
            fid = db.add_finding(
                scan_id,
                title    = f"Exposed {secret.get('type', 'Secret')}",
                severity = secret.get("severity", "high"),
                asset    = secret.get("url", target),
                detail   = secret.get("context", "")[:200],
                module   = "secret",
            )
            all_findings.append({
                "id": fid, "title": f"Exposed {secret.get('type', 'Secret')}",
                "severity": secret.get("severity", "high"),
                "asset": secret.get("url", target),
                "detail": secret.get("context", "")[:200],
                "module": "secret", "curl_poc": "",
            })
    else:
        console.print("  [dim]  Secret scanner disabled in config[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 14 — CORS Misconfiguration Testing")
    if cfg.get("cors_enabled", True):
        cors_mod    = CORSCheckerModule(timeout=timeout, proxy=proxy)
        cors_result = cors_mod.run(target, urls=alive_urls[:5])
        scan_notes["cors"] = cors_result

        for finding in cors_result.get("findings", []):
            fid = db.add_finding(
                scan_id,
                title    = f"CORS: {finding.get('label', 'Misconfiguration')}",
                severity = finding.get("severity", "medium"),
                asset    = finding.get("url", target),
                detail   = finding.get("detail", ""),
                module   = "cors",
            )
            all_findings.append({
                "id": fid, "title": f"CORS: {finding.get('label', 'Misconfiguration')}",
                "severity": finding.get("severity", "medium"),
                "asset": finding.get("url", target),
                "detail": finding.get("detail", ""),
                "module": "cors", "curl_poc": "",
            })
    else:
        console.print("  [dim]  CORS testing disabled in config[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("STEP 15 — Breach Intelligence (OSINTCat)")
    breach_data = check_breach(target, cfg.get("osintcat_api_key", ""))
    if breach_data:
        console.print(Panel(
            f"[yellow]{json.dumps(breach_data, indent=2)[:500]}[/yellow]",
            title="[bold red]Breach Data Found[/bold red]",
            border_style="red",
        ))

    # ═══════════════════════════════════════════════════════════════════════════
    if verify and all_findings:
        _section("STEP 16 — Vulnerability Verification")
        for f in all_findings:
            curl_cmd = f.get("curl_poc", "")
            if not curl_cmd or not curl_cmd.strip().startswith("curl"):
                continue

            console.print(f"  [dim]  Verifying: {f.get('title', '?')}…[/dim]")
            status, body, ms = verify_with_curl(curl_cmd)

            verify_ai = ai.verify_finding(
                vuln_title       = f.get("title", "?"),
                curl_response    = body,
                status_code      = status,
                response_time_ms = ms,
            )

            if verify_ai and verify_ai.get("confirmed"):
                f["confirmed"] = True
                console.print(f"  [bold green]  ✔ CONFIRMED: {f.get('title', '?')}[/bold green]")
                console.print(f"  [dim]  Evidence: {verify_ai.get('evidence', '?')[:120]}[/dim]")

                rep = ai.write_report({**f, "evidence": verify_ai.get("evidence", "")})
                db.confirm_finding(f["id"], report=rep)
                f["report"] = rep
            else:
                reason = (verify_ai or {}).get("false_positive_reason", "")
                console.print(f"  [dim]  Unconfirmed: {f.get('title', '?')} — {reason[:80]}[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    _section("SCAN COMPLETE")

    all_findings = db.get_findings(scan_id)
    _severity_panel(all_findings)
    print_findings_table(all_findings, title=f"All Findings — {target}")

    # ── Report ────────────────────────────────────────────────────────────────
    if report:
        _section("STEP 17 — Report Generation")
        save_report(
            target          = target,
            findings        = all_findings,
            reports_dir     = REPORTS_DIR,
            breach_data     = breach_data,
            alive_count     = len(alive_hosts),
            subdomain_count = len(subdomains),
            scan_notes      = scan_notes,      # ← now populated with all module data
        )

    db.finish_scan(scan_id)
    console.print(f"\n  [bold green]✔ Scan #{scan_id} finished.[/bold green]")
    db.close()


# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def history():
    """[bold cyan]Show past scans from the database.[/bold cyan]"""
    _print_banner()
    db    = Database(DB_FILE)
    scans = db.list_scans()
    db.close()

    if not scans:
        console.print("  [dim]No scans recorded yet. Run: evhunter recon <target>[/dim]")
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
    notes    = db.get_all_notes(scan_id)

    scans = [s for s in db.list_scans() if s["id"] == scan_id]
    if not scans:
        console.print(f"[red]  Scan #{scan_id} not found.[/red]")
        db.close()
        raise typer.Exit()

    target = scans[0]["target"]
    db.close()

    _section(f"Regenerating report for scan #{scan_id} — {target}")
    save_report(target, findings, REPORTS_DIR, scan_notes=notes)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from config import is_configured
    skip_args = {"configure", "--help", "-h", "--version"}
    needs_check = len(sys.argv) > 1 and not any(a in skip_args for a in sys.argv[1:])
    if needs_check and not is_configured():
        console.print(Panel(
            "[bold yellow]⚙  First run detected.[/bold yellow]\n\n"
            "Run [bold cyan]python main.py configure[/bold cyan] to set up EVHunter.",
            border_style="yellow",
        ))
        sys.exit(1)

    app()
