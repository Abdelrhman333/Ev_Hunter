"""
BugHunter - Recon Module
Pipeline: nmap → subdomain enum → filter → httpx → nuclei → AI → breach check
"""

import json
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _tool_ok(name: str) -> bool:
    return shutil.which(name) is not None

def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Run a subprocess, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"tool not found: {cmd[0]}"

def _status(msg: str, style: str = "cyan"):
    console.print(f"  [bold {style}]▸[/bold {style}] {msg}")


# ── 1. Nmap Scan ─────────────────────────────────────────────────────────────

def run_nmap(target: str, fast: bool = True) -> dict:
    """
    Run nmap and return a compact summary dict (AI-friendly, low tokens).
    """
    if not _tool_ok("nmap"):
        console.print("  [yellow]  nmap not found — skipping port scan[/yellow]")
        return {"error": "nmap not installed"}

    _status("Running nmap port scan…")
    flags = ["-T4", "--open", "-sV", "--version-light"]
    if fast:
        flags += ["-F"]  # top 100 ports
    else:
        flags += ["--top-ports", "1000"]

    rc, out, err = _run(["nmap"] + flags + ["-oX", "-", target], timeout=180)
    if rc != 0 and rc != -1:
        console.print(f"  [red]  nmap error: {err[:100]}[/red]")
        return {"error": err[:100]}

    # Parse into compact dict
    summary: dict = {"target": target, "ports": []}
    for line in out.splitlines():
        # Match: port/proto  state  service  version
        m = re.search(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            summary["ports"].append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip()[:40],  # truncate
            })

    console.print(f"  [green]  ✔ Found {len(summary['ports'])} open port(s)[/green]")
    return summary


# ── 2. Subdomain Enumeration ──────────────────────────────────────────────────

def _subfinder(domain: str) -> set[str]:
    if not _tool_ok("subfinder"):
        console.print("  [yellow]  subfinder not found — skipping[/yellow]")
        return set()
    _status("Running subfinder…")
    rc, out, _ = _run(["subfinder", "-d", domain, "-silent", "-all"], timeout=120)
    results = {line.strip().lower() for line in out.splitlines() if line.strip()}
    console.print(f"  [green]  ✔ subfinder → {len(results)} subdomains[/green]")
    return results


def _crtsh(domain: str) -> set[str]:
    """Fetch subdomains from crt.sh certificate transparency logs."""
    _status("Querying crt.sh…")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BugHunter/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        results: set[str] = set()
        for entry in data:
            names = entry.get("name_value", "").splitlines()
            for n in names:
                n = n.strip().lstrip("*.").lower()
                if domain in n:
                    results.add(n)
        console.print(f"  [green]  ✔ crt.sh     → {len(results)} subdomains[/green]")
        return results
    except Exception as e:
        console.print(f"  [yellow]  crt.sh failed: {e}[/yellow]")
        return set()


def enumerate_subdomains(domain: str) -> list[str]:
    """Combine subfinder + crt.sh, deduplicate, filter invalid."""
    all_subs: set[str] = set()
    all_subs |= _subfinder(domain)
    all_subs |= _crtsh(domain)

    # Filter: must contain the root domain and be valid-ish
    valid = {
        s for s in all_subs
        if domain in s
        and re.match(r"^[a-z0-9.\-]+$", s)
        and len(s) < 100
    }
    console.print(f"  [bold green]  ✔ Total unique subdomains: {len(valid)}[/bold green]")
    return sorted(valid)


# ── 3. HTTP Probing ───────────────────────────────────────────────────────────

def _probe_single(host: str, timeout: int = 5) -> Optional[dict]:
    """Try https then http, return compact info or None."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "BugHunter/1.0"},
                method="GET",
            )
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed = int((time.time() - t0) * 1000)
                body    = resp.read(512).decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                return {
                    "url":     url,
                    "status":  resp.status,
                    "ms":      elapsed,
                    "server":  headers.get("Server", ""),
                    "title":   re.search(r"<title>(.*?)</title>", body, re.I),
                    "headers": {k: v for k, v in list(headers.items())[:6]},
                    "body_snippet": body[:200],
                }
        except Exception:
            continue
    return None


def probe_alive(subdomains: list[str], max_workers: int = 20) -> list[dict]:
    """
    Probe subdomains concurrently using threading (stdlib only).
    Returns list of alive host info dicts.
    """
    _status(f"Probing {len(subdomains)} subdomains for HTTP(S)…")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    alive: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("  [progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("  Probing…", total=len(subdomains))

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_probe_single, sd): sd for sd in subdomains}
            for future in as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    # Fix title
                    if result["title"]:
                        result["title"] = result["title"].group(1)[:60]
                    alive.append(result)

    console.print(f"  [bold green]  ✔ Alive: {len(alive)} / {len(subdomains)}[/bold green]")
    return alive


# ── 4. Nuclei Scan ────────────────────────────────────────────────────────────

def run_nuclei(targets: list[str]) -> list[dict]:
    """
    Run nuclei for low-hanging fruit.
    Returns compact list of findings.
    """
    if not _tool_ok("nuclei"):
        console.print("  [yellow]  nuclei not found — skipping[/yellow]")
        return []

    _status("Running nuclei (low-hanging fruit)…")

    # Write targets to temp file
    tmp = Path("/tmp/bh_targets.txt")
    tmp.write_text("\n".join(targets))

    rc, out, err = _run([
        "nuclei", "-l", str(tmp),
        "-severity", "critical,high,medium",
        "-silent", "-json",
        "-timeout", "5",
        "-rate-limit", "20",
        "-bulk-size", "10",
    ], timeout=300)

    findings: list[dict] = []
    for line in out.splitlines():
        try:
            hit = json.loads(line)
            findings.append({
                "template": hit.get("template-id", ""),
                "name":     hit.get("info", {}).get("name", ""),
                "severity": hit.get("info", {}).get("severity", ""),
                "url":      hit.get("matched-at", ""),
                "extracted": hit.get("extracted-results", [])[:3],
            })
        except Exception:
            continue

    console.print(f"  [bold {'red' if findings else 'green'}]  ✔ nuclei → {len(findings)} hit(s)[/bold {'red' if findings else 'green'}]")
    return findings


# ── 5. Breach Check ──────────────────────────────────────────────────────────

def check_breach(domain: str, api_key: str) -> Optional[dict]:
    """Query OSINTCat for breach data on the domain."""
    _status("Checking breach databases (OSINTCat)…")

    url    = f"https://www.osintcat.net/api/breach?query={domain}"
    req    = urllib.request.Request(url, headers={"X-API-KEY": api_key})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.json() if hasattr(resp, "json") else json.loads(resp.read())
            console.print(f"  [green]  ✔ Breach query complete[/green]")
            return data
    except urllib.error.HTTPError as e:
        console.print(f"  [yellow]  OSINTCat error {e.code}[/yellow]")
        return None
    except Exception as e:
        console.print(f"  [yellow]  Breach check failed: {e}[/yellow]")
        return None


# ── 6. Curl Verification ─────────────────────────────────────────────────────

def verify_with_curl(curl_cmd: str) -> tuple[int, str, int]:
    """
    Execute a curl PoC command and return (status_code, body_snippet, ms).
    """
    # Sanitize: only allow curl commands
    if not curl_cmd.strip().startswith("curl"):
        return -1, "invalid command", 0

    # Add useful flags if missing
    if "-s" not in curl_cmd:
        curl_cmd = curl_cmd.replace("curl ", "curl -s -o - -w '\\n%{http_code}' ", 1)

    t0 = time.time()
    rc, out, err = _run(curl_cmd.split(), timeout=15)
    ms = int((time.time() - t0) * 1000)

    # Try to extract status code from last line
    lines = out.strip().splitlines()
    status = -1
    if lines:
        try:
            status = int(lines[-1])
            body   = "\n".join(lines[:-1])[:400]
        except ValueError:
            body = out[:400]

    return status, body, ms


# ── Pretty display helpers ────────────────────────────────────────────────────

def print_alive_table(alive: list[dict]):
    tbl = Table(
        title=f"  [bold]Alive Hosts ({len(alive)})[/bold]",
        box=box.SIMPLE_HEAVY,
        border_style="bright_blue",
        show_header=True,
        header_style="bold cyan",
    )
    tbl.add_column("URL",     style="white", no_wrap=True, max_width=50)
    tbl.add_column("Status",  justify="center", width=8)
    tbl.add_column("Title",   style="dim",   max_width=40)
    tbl.add_column("Server",  style="dim",   max_width=20)
    tbl.add_column("ms",      justify="right", width=6)

    for h in sorted(alive, key=lambda x: x["status"]):
        sc = h["status"]
        sc_style = "green" if sc == 200 else "yellow" if sc < 400 else "red"
        tbl.add_row(
            h["url"],
            f"[{sc_style}]{sc}[/{sc_style}]",
            h.get("title") or "—",
            h.get("server") or "—",
            str(h.get("ms", "?")),
        )
    console.print(tbl)


def print_findings_table(findings: list[dict], title: str = "Findings"):
    from rich.text import Text
    SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}

    tbl = Table(
        title=f"  [bold]{title}[/bold]",
        box=box.SIMPLE_HEAVY,
        border_style="bright_red",
        header_style="bold cyan",
    )
    tbl.add_column("Severity",  width=10)
    tbl.add_column("Title",     max_width=40)
    tbl.add_column("Asset",     max_width=40, style="dim")
    tbl.add_column("Confirmed", width=11, justify="center")

    for f in findings:
        sev   = (f.get("severity") or "info").lower()
        color = SEV_COLOR.get(sev, "white")
        tbl.add_row(
            f"[{color}]{sev.upper()}[/{color}]",
            f.get("title", "?"),
            f.get("asset", "?"),
            "[green]✔ YES[/green]" if f.get("confirmed") else "[dim]Pending[/dim]",
        )
    console.print(tbl)
