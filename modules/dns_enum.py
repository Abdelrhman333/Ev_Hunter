"""
EVHunter — DNS Enumeration Module
Collects A, AAAA, MX, TXT, NS, CNAME, SOA records.
Attempts zone transfer (AXFR) on each nameserver.
Checks SPF, DMARC, DKIM presence.
"""

import re
import socket
import subprocess
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()


class DNSEnumModule(ScannerModule):
    name        = "dns"
    description = "DNS record collection, zone transfer attempt, SPF/DMARC check"

    def run(self, target: str, **kwargs) -> dict[str, Any]:
        self._start_timer()
        self._status(f"DNS enumeration for [cyan]{target}[/cyan]…")
        result: dict[str, Any] = {
            "ok":      True,
            "target":  target,
            "records": {},
            "zone_transfer": [],
            "security": {},
            "issues":  [],
        }

        # ── Collect record types ──────────────────────────────────────────────
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
            records = self._query(target, rtype)
            if records:
                result["records"][rtype] = records

        # ── Security checks ───────────────────────────────────────────────────
        txt_all = " ".join(result["records"].get("TXT", []))

        result["security"]["spf"]   = "v=spf1"  in txt_all
        result["security"]["dmarc"] = self._check_dmarc(target)
        result["security"]["dkim"]  = self._check_dkim(target)

        if not result["security"]["spf"]:
            result["issues"].append({
                "type": "Missing SPF", "severity": "medium",
                "detail": "No SPF record found — domain may be spoofable",
                "record": "",
            })
        if not result["security"]["dmarc"]:
            result["issues"].append({
                "type": "Missing DMARC", "severity": "medium",
                "detail": "No DMARC policy found — phishing risk",
                "record": "",
            })

        # ── Zone transfer ─────────────────────────────────────────────────────
        nameservers = result["records"].get("NS", [])
        for ns in nameservers[:3]:
            ns_clean = ns.rstrip(".")
            zt = self._zone_transfer(target, ns_clean)
            if zt:
                result["zone_transfer"].extend(zt)
                result["issues"].append({
                    "type":     "Zone Transfer Exposed",
                    "severity": "critical",
                    "detail":   f"Nameserver {ns_clean} allows AXFR zone transfer!",
                    "record":   ns_clean,
                })

        # ── Dangling CNAME check ──────────────────────────────────────────────
        cnames = result["records"].get("CNAME", [])
        for cname in cnames:
            cname_clean = cname.rstrip(".")
            if not self._resolves(cname_clean):
                result["issues"].append({
                    "type":     "Dangling CNAME",
                    "severity": "high",
                    "detail":   f"CNAME {cname_clean} does not resolve — potential subdomain takeover",
                    "record":   cname_clean,
                })

        self._ok(f"DNS done — {len(result['records'])} record types, "
                 f"{len(result['issues'])} issue(s) [{self._elapsed()}]")
        self._print_table(result)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _query(self, domain: str, rtype: str) -> list[str]:
        try:
            rc, out, _ = self._dig(domain, rtype)
            lines = [
                l.strip() for l in out.splitlines()
                if l.strip() and not l.startswith(";")
                and rtype in l.split()
            ]
            return [" ".join(l.split()[4:]) for l in lines if len(l.split()) >= 5]
        except Exception:
            return []

    def _dig(self, domain: str, rtype: str) -> tuple[int, str, str]:
        try:
            r = subprocess.run(
                ["dig", "+noall", "+answer", rtype, domain],
                capture_output=True, text=True, timeout=10
            )
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            # Fall back to socket for A records
            if rtype == "A":
                try:
                    ips = [info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET)]
                    return 0, "\n".join(f". 300 IN A {ip}" for ip in set(ips)), ""
                except Exception:
                    pass
            return -1, "", "dig not found"
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"

    def _zone_transfer(self, domain: str, nameserver: str) -> list[str]:
        try:
            r = subprocess.run(
                ["dig", f"@{nameserver}", "AXFR", domain],
                capture_output=True, text=True, timeout=10
            )
            if "Transfer failed" in r.stdout or r.returncode != 0:
                return []
            lines = [l.strip() for l in r.stdout.splitlines()
                     if l.strip() and not l.startswith(";")]
            return lines[:50]  # cap
        except Exception:
            return []

    def _check_dmarc(self, domain: str) -> bool:
        records = self._query(f"_dmarc.{domain}", "TXT")
        return any("v=DMARC1" in r for r in records)

    def _check_dkim(self, domain: str) -> bool:
        # Common DKIM selectors
        for selector in ("default", "google", "mail", "k1", "dkim"):
            records = self._query(f"{selector}._domainkey.{domain}", "TXT")
            if any("v=DKIM1" in r or "p=" in r for r in records):
                return True
        return False

    def _resolves(self, domain: str) -> bool:
        try:
            socket.getaddrinfo(domain, None)
            return True
        except Exception:
            return False

    def _print_table(self, result: dict):
        if not result["records"]:
            return
        tbl = Table(
            title="  [bold]DNS Records[/bold]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            border_style="bright_blue",
        )
        tbl.add_column("Type",   width=8)
        tbl.add_column("Value",  style="dim", max_width=70)
        for rtype, vals in result["records"].items():
            for v in vals[:5]:
                tbl.add_row(rtype, v[:100])
        console.print(tbl)
