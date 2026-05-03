"""
EVHunter — Core Recon Module  v3.0
Pipeline: nmap → subdomain enum → httpx → nuclei → breach check

Bug fixes v3.0:
  - CRITICAL: t0 undefined in HTTPError except block — moved before try
  - Fixed curl rewrite logic (uses shlex, only adds flags if missing)
  - Added Wayback Machine historical endpoint discovery
  - Added wordlist-based subdomain brute forcing
  - Enhanced HTTP probe with full header collection
  - Better nuclei output parsing
"""

import json
import re
import shlex
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()

SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}

# Common subdomains wordlist (top ~200 patterns)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "uat",
    "app", "apps", "m", "mobile", "portal", "dashboard", "panel", "backend",
    "internal", "intranet", "vpn", "remote", "gateway", "proxy",
    "blog", "shop", "store", "static", "cdn", "assets", "media", "img", "images",
    "login", "auth", "sso", "oauth", "accounts", "id", "identity",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "jenkins", "ci", "cd", "gitlab", "github", "jira", "confluence", "wiki",
    "grafana", "kibana", "splunk", "monitoring", "metrics", "logs", "logging",
    "smtp", "imap", "pop3", "mx", "webmail", "mail2",
    "backup", "backups", "archive", "old", "legacy", "deprecated",
    "api2", "api3", "v1", "v2", "v3", "rest", "graphql",
    "docs", "documentation", "help", "support", "status", "health",
    "s3", "storage", "files", "uploads", "download", "downloads",
    "beta", "alpha", "preview", "pre", "preprod", "qa",
    "pay", "payments", "checkout", "billing", "invoice",
    "search", "analytics", "tracking", "pixel",
    "aws", "gcp", "azure", "cloud",
    "ldap", "ad", "exchange",
    "k8s", "kubernetes", "docker", "swarm",
    "node", "php", "python", "java", "ruby",
    "test1", "test2", "dev1", "dev2", "stage",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tool_ok(name: str) -> bool:
    return shutil.which(name) is not None

def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"tool not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)

def _status(msg: str, style: str = "cyan"):
    console.print(f"  [bold {style}]▸[/bold {style}] {msg}")


# ── 1. Nmap Scan ──────────────────────────────────────────────────────────────

def run_nmap(target: str, fast: bool = True) -> dict:
    if not _tool_ok("nmap"):
        console.print("  [yellow]  nmap not found — skipping port scan[/yellow]")
        return {"error": "nmap not installed", "target": target, "ports": []}

    _status("Running nmap port scan…")
    flags = ["-T4", "--open", "-sV", "--version-light", "-sC"]
    flags += ["-F"] if fast else ["--top-ports", "1000"]

    rc, out, err = _run(["nmap"] + flags + ["-oX", "-", target], timeout=300)
    if rc not in (0, -1):
        console.print(f"  [red]  nmap error: {err[:150]}[/red]")
        return {"error": err[:100], "target": target, "ports": []}

    summary: dict = {"target": target, "ports": [], "os_guess": "", "scripts": []}

    for line in out.splitlines():
        # Open ports: "80/tcp   open  http    nginx 1.20"
        m = re.search(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            summary["ports"].append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip()[:80],
            })
        os_m = re.search(r"OS details:\s+(.+)", line)
        if os_m:
            summary["os_guess"] = os_m.group(1).strip()[:80]
        # Script output (for vuln scripts)
        script_m = re.search(r"\|\s+(.+):\s+(.+)", line)
        if script_m:
            summary["scripts"].append(f"{script_m.group(1)}: {script_m.group(2).strip()[:100]}")

    console.print(f"  [green]  ✔ Found {len(summary['ports'])} open port(s)[/green]")
    for p in summary["ports"]:
        console.print(f"    [dim]{p['port']}/{p['proto']}  {p['service']}  {p['version']}[/dim]")
    if summary["os_guess"]:
        console.print(f"  [dim]    OS: {summary['os_guess']}[/dim]")
    return summary


# ── 2. Subdomain Enumeration ──────────────────────────────────────────────────

def _subfinder(domain: str) -> set[str]:
    if not _tool_ok("subfinder"):
        console.print("  [yellow]  subfinder not found — skipping[/yellow]")
        return set()
    _status("Running subfinder…")
    rc, out, _ = _run(["subfinder", "-d", domain, "-silent", "-all"], timeout=180)
    results = {line.strip().lower() for line in out.splitlines() if line.strip()}
    console.print(f"  [green]  ✔ subfinder → {len(results)} subdomains[/green]")
    return results


def _crtsh(domain: str) -> set[str]:
    _status("Querying crt.sh…")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EVHunter/3.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        results: set[str] = set()
        for entry in data:
            for n in entry.get("name_value", "").splitlines():
                n = n.strip().lstrip("*.").lower()
                if domain in n and re.match(r"^[a-z0-9.\-]+$", n):
                    results.add(n)
        console.print(f"  [green]  ✔ crt.sh     → {len(results)} subdomains[/green]")
        return results
    except Exception as e:
        console.print(f"  [yellow]  crt.sh failed: {e}[/yellow]")
        return set()


def _wayback(domain: str) -> set[str]:
    _status("Querying Wayback Machine CDX API…")
    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=1000"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EVHunter/3.0"})
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read())
        results: set[str] = set()
        for row in data[1:]:
            try:
                m = re.match(r"https?://([^/:?]+)", row[0])
                if m:
                    host = m.group(1).lower()
                    if domain in host:
                        results.add(host)
            except Exception:
                pass
        console.print(f"  [green]  ✔ Wayback     → {len(results)} subdomains[/green]")
        return results
    except Exception as e:
        console.print(f"  [yellow]  Wayback CDX failed: {e}[/yellow]")
        return set()


def _bruteforce_subdomains(domain: str, max_workers: int = 30) -> set[str]:
    """Concurrent DNS brute force using the built-in wordlist."""
    import socket
    _status(f"Brute-forcing {len(SUBDOMAIN_WORDLIST)} common subdomains…")
    found: set[str] = set()

    def resolve(sub: str) -> Optional[str]:
        fqdn = f"{sub}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET)
            return fqdn
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(resolve, sub): sub for sub in SUBDOMAIN_WORDLIST}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.add(result)

    console.print(f"  [green]  ✔ Bruteforce  → {len(found)} subdomains[/green]")
    return found


def enumerate_subdomains(domain: str, use_wayback: bool = True,
                          use_bruteforce: bool = True) -> list[str]:
    all_subs: set[str] = set()
    all_subs |= _subfinder(domain)
    all_subs |= _crtsh(domain)
    if use_wayback:
        all_subs |= _wayback(domain)
    if use_bruteforce:
        all_subs |= _bruteforce_subdomains(domain)

    valid = {
        s for s in all_subs
        if domain in s
        and re.match(r"^[a-z0-9.\-]+$", s)
        and len(s) < 100
        and not s.startswith("-")
    }
    console.print(f"  [bold green]  ✔ Total unique subdomains: {len(valid)}[/bold green]")
    return sorted(valid)


# ── 3. HTTP Probing ───────────────────────────────────────────────────────────

def _probe_single(host: str, timeout: int = 8) -> Optional[dict]:
    """
    Try https then http; return compact info or None.

    BUG FIX v3.0: t0 was referenced in the except block before being assigned.
    Moved t0 = time.time() to BEFORE the try block.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}" if not host.startswith("http") else host
        # FIX: define t0 BEFORE the try block so it's always available in except
        t0 = time.time()
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; EVHunter/3.0)",
                    "Accept":     "text/html,*/*",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed = int((time.time() - t0) * 1000)
                body    = resp.read(8192).decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)

                # Detect interesting security header presence/absence
                security_headers = {
                    "hsts":   "strict-transport-security" in headers,
                    "csp":    "content-security-policy" in headers,
                    "xfo":    "x-frame-options" in headers,
                    "xcto":   "x-content-type-options" in headers,
                    "cors":   "access-control-allow-origin" in headers,
                }

                return {
                    "url":             url,
                    "status":          resp.status,
                    "ms":              elapsed,
                    "server":          headers.get("server", ""),
                    "title":           title_m.group(1).strip()[:80] if title_m else "",
                    "headers":         dict(list(headers.items())[:20]),
                    "body_snippet":    body[:500],
                    "content_type":    headers.get("content-type", ""),
                    "security_headers": security_headers,
                    "x_powered_by":    headers.get("x-powered-by", ""),
                    "cookies":         headers.get("set-cookie", ""),
                }
        except urllib.error.HTTPError as e:
            elapsed = int((time.time() - t0) * 1000)
            return {
                "url":    url,
                "status": e.code,
                "ms":     elapsed,
                "server": "",
                "title":  "",
                "headers": {},
                "body_snippet": "",
                "content_type": "",
                "security_headers": {},
                "x_powered_by": "",
                "cookies": "",
            }
        except Exception:
            continue
    return None


def probe_alive(subdomains: list[str], max_workers: int = 20, timeout: int = 8) -> list[dict]:
    _status(f"Probing {len(subdomains)} host(s) for HTTP(S)…")
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
            futures = {pool.submit(_probe_single, sd, timeout): sd for sd in subdomains}
            for future in as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result and result["status"] not in (-1,):
                    alive.append(result)

    console.print(f"  [bold green]  ✔ Alive: {len(alive)} / {len(subdomains)}[/bold green]")
    return alive


# ── 4. Nuclei Scan ────────────────────────────────────────────────────────────

def run_nuclei(targets: list[str]) -> list[dict]:
    if not _tool_ok("nuclei"):
        console.print("  [yellow]  nuclei not found — skipping[/yellow]")
        return []

    _status("Running nuclei (low-hanging fruit)…")

    tmp = Path("/tmp/evh_targets.txt")
    tmp.write_text("\n".join(targets))

    rc, out, err = _run([
        "nuclei", "-l", str(tmp),
        "-severity", "critical,high,medium",
        "-silent", "-json",
        "-timeout", "8",
        "-rate-limit", "20",
        "-bulk-size", "10",
        "-no-interactsh",  # avoid external callbacks without consent
    ], timeout=600)

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
                "curl_cmd": hit.get("curl-command", ""),
                "tags":     hit.get("info", {}).get("tags", []),
            })
        except Exception:
            continue

    color = "red" if findings else "green"
    console.print(f"  [bold {color}]  ✔ nuclei → {len(findings)} hit(s)[/bold {color}]")

    # Show critical/high immediately
    for hit in findings:
        sev = hit.get("severity", "").lower()
        if sev in ("critical", "high"):
            color = "bold red" if sev == "critical" else "red"
            console.print(f"    [{color}]  ⚡ {sev.upper()}[/{color}] {hit['name']} @ {hit['url'][:60]}")

    return findings


# ── 5. Breach Check ───────────────────────────────────────────────────────────

def check_breach(domain: str, api_key: str) -> Optional[dict]:
    if not api_key:
        console.print("  [dim]  No OSINTCat key configured — skipping breach check[/dim]")
        return None

    _status("Checking breach databases (OSINTCat)…")
    url = f"https://www.osintcat.net/api/breach?query={domain}"
    req = urllib.request.Request(
        url, headers={"X-API-KEY": api_key, "User-Agent": "EVHunter/3.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
            console.print(f"  [green]  ✔ Breach query complete[/green]")
            return data
    except urllib.error.HTTPError as e:
        console.print(f"  [yellow]  OSINTCat error {e.code}[/yellow]")
        return None
    except Exception as e:
        console.print(f"  [yellow]  Breach check failed: {e}[/yellow]")
        return None


# ── 6. Curl Verification ──────────────────────────────────────────────────────

def verify_with_curl(curl_cmd: str, timeout: int = 15) -> tuple[int, str, int]:
    """
    Execute a curl PoC command safely.
    Returns (status_code, body_snippet, elapsed_ms).
    """
    curl_cmd = curl_cmd.strip()

    if not curl_cmd.lower().startswith("curl"):
        return -1, "invalid command — must start with 'curl'", 0

    # Remove shell metacharacters
    if any(c in curl_cmd for c in ("|", ";", "`", "$(")):
        curl_cmd = re.sub(r"[|;`$].*", "", curl_cmd)

    # Add flags if missing
    additions = []
    if "-o -" not in curl_cmd and "--output -" not in curl_cmd:
        additions.append("-o -")
    if "-w " not in curl_cmd and "--write-out" not in curl_cmd:
        additions.append(r"-w '\n%{http_code}'")
    if "-s" not in curl_cmd.split() and "--silent" not in curl_cmd:
        additions.append("-s")
    if "--max-time" not in curl_cmd:
        additions.append("--max-time 10")
    if "-k" not in curl_cmd.split() and "--insecure" not in curl_cmd:
        additions.append("-k")  # ignore SSL errors in PoC testing

    if additions:
        curl_cmd = "curl " + " ".join(additions) + " " + curl_cmd[5:]

    t0 = time.time()
    try:
        cmd_parts = shlex.split(curl_cmd)
        rc, out, err = _run(cmd_parts, timeout=timeout)
    except ValueError:
        cmd_parts = curl_cmd.split()
        rc, out, err = _run(cmd_parts, timeout=timeout)
    ms = int((time.time() - t0) * 1000)

    lines  = out.strip().splitlines()
    status = -1
    body   = out[:500]

    if lines:
        try:
            status = int(lines[-1])
            body   = "\n".join(lines[:-1])[:500]
        except ValueError:
            pass

    return status, body, ms


# ── Pretty Display Helpers ────────────────────────────────────────────────────

def print_alive_table(alive: list[dict]):
    tbl = Table(
        title=f"  [bold]Alive Hosts ({len(alive)})[/bold]",
        box=box.SIMPLE_HEAVY,
        border_style="bright_blue",
        header_style="bold cyan",
    )
    tbl.add_column("URL",    style="white", no_wrap=True, max_width=50)
    tbl.add_column("Status", justify="center", width=8)
    tbl.add_column("Title",  style="dim",   max_width=35)
    tbl.add_column("Server", style="dim",   max_width=20)
    tbl.add_column("HSTS",   width=6,  justify="center")
    tbl.add_column("CSP",    width=6,  justify="center")
    tbl.add_column("ms",     justify="right", width=6)

    for h in sorted(alive, key=lambda x: x["status"]):
        sc       = h["status"]
        sc_style = "green" if sc == 200 else "yellow" if sc < 400 else "red"
        sh       = h.get("security_headers", {})
        tbl.add_row(
            h["url"][:50],
            f"[{sc_style}]{sc}[/{sc_style}]",
            (h.get("title") or "—")[:35],
            (h.get("server") or "—")[:20],
            "[green]✔[/green]" if sh.get("hsts") else "[red]✗[/red]",
            "[green]✔[/green]" if sh.get("csp")  else "[red]✗[/red]",
            str(h.get("ms", "?")),
        )
    console.print(tbl)


def print_findings_table(findings: list[dict], title: str = "Findings"):
    if not findings:
        console.print("  [dim]  No findings recorded.[/dim]")
        return
    tbl = Table(
        title=f"  [bold]{title}[/bold]",
        box=box.SIMPLE_HEAVY,
        border_style="bright_red",
        header_style="bold cyan",
    )
    tbl.add_column("Sev",       width=10)
    tbl.add_column("Title",     max_width=45)
    tbl.add_column("Asset",     max_width=35, style="dim")
    tbl.add_column("Module",    width=12, style="dim")
    tbl.add_column("Confirmed", width=11, justify="center")

    for f in findings:
        sev   = (f.get("severity") or "info").lower()
        color = SEV_COLOR.get(sev, "white")
        tbl.add_row(
            f"[{color}]{sev.upper()}[/{color}]",
            f.get("title", "?")[:45],
            f.get("asset", "?")[:35],
            f.get("module", "ai")[:12],
            "[green]✔ YES[/green]" if f.get("confirmed") else "[dim]Pending[/dim]",
        )
    console.print(tbl)
