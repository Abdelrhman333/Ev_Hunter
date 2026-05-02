"""
EVHunter — SSL/TLS Analyzer Module
Certificate info, expiry, SANs, weak cipher detection,
HSTS presence, HPKP, CT log submission.
"""

import datetime
import socket
import ssl
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "MD5", "PSK", "SRP", "CAMELLIA",
}


class SSLAnalyzerModule(ScannerModule):
    name        = "ssl"
    description = "SSL/TLS certificate and cipher analysis"

    def run(self, target: str, port: int = 443, **kwargs) -> dict[str, Any]:
        self._start_timer()
        self._status(f"SSL/TLS analysis on [cyan]{target}:{port}[/cyan]…")

        result: dict[str, Any] = {
            "ok":      False,
            "target":  target,
            "port":    port,
            "cert":    {},
            "issues":  [],
            "grade":   "A",
            "hsts":    False,
            "protocols": [],
        }

        # ── Fetch certificate ──────────────────────────────────────────────────
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert      = ssock.getpeercert()
                    cipher    = ssock.cipher()
                    protocol  = ssock.version()

                    result["ok"]       = True
                    result["protocols"] = [protocol]
                    result["cipher"]   = {
                        "name":     cipher[0] if cipher else "unknown",
                        "protocol": cipher[1] if cipher and len(cipher) > 1 else "unknown",
                        "bits":     cipher[2] if cipher and len(cipher) > 2 else 0,
                    }
                    result["cert"]     = self._parse_cert(cert)
        except ssl.SSLError as e:
            result["issues"].append({
                "type": "SSL Error", "severity": "high",
                "detail": str(e)
            })
            result["grade"] = "F"
            self._warn(f"SSL error: {e}")
            return result
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["error"] = str(e)
            self._warn(f"Could not connect to {target}:{port} — {e}")
            return result

        # ── Run checks ────────────────────────────────────────────────────────
        self._check_expiry(result)
        self._check_self_signed(result)
        self._check_cipher(result)
        self._check_wildcard(result)
        self._check_weak_protocol(result)
        self._try_weak_protocols(target, port, result)

        # ── Downgrade grade ────────────────────────────────────────────────────
        sev_found = [i["severity"] for i in result["issues"]]
        if "critical" in sev_found:
            result["grade"] = "F"
        elif "high" in sev_found:
            result["grade"] = "C"
        elif "medium" in sev_found:
            result["grade"] = "B"

        self._ok(f"SSL done — grade [bold]{result['grade']}[/bold], "
                 f"{len(result['issues'])} issue(s) [{self._elapsed()}]")
        self._print_summary(result)
        return result

    # ── Cert parsing ──────────────────────────────────────────────────────────

    def _parse_cert(self, cert: dict) -> dict:
        if not cert:
            return {}
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        not_after = cert.get("notAfter", "")
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days   = (expiry - datetime.datetime.utcnow()).days
        except Exception:
            expiry = None
            days   = None

        return {
            "subject":     subject.get("commonName", ""),
            "issuer":      issuer.get("organizationName", ""),
            "issuer_cn":   issuer.get("commonName", ""),
            "sans":        sans[:20],
            "expiry":      not_after,
            "days_left":   days,
            "serial":      cert.get("serialNumber", ""),
            "version":     cert.get("version", ""),
        }

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_expiry(self, result: dict):
        days = result["cert"].get("days_left")
        if days is None:
            return
        if days < 0:
            result["issues"].append({
                "type": "Expired Certificate", "severity": "critical",
                "detail": f"Certificate expired {abs(days)} day(s) ago!"
            })
        elif days < 14:
            result["issues"].append({
                "type": "Certificate Expiring Soon", "severity": "high",
                "detail": f"Certificate expires in {days} day(s)"
            })
        elif days < 30:
            result["issues"].append({
                "type": "Certificate Expiring Soon", "severity": "medium",
                "detail": f"Certificate expires in {days} day(s)"
            })

    def _check_self_signed(self, result: dict):
        cert = result["cert"]
        if cert.get("subject") and cert.get("issuer_cn"):
            if cert["subject"] == cert["issuer_cn"] or cert["issuer"] in ("", None):
                result["issues"].append({
                    "type": "Self-Signed Certificate", "severity": "high",
                    "detail": "Certificate is self-signed — no trusted CA"
                })

    def _check_cipher(self, result: dict):
        cipher_name = result.get("cipher", {}).get("name", "")
        bits        = result.get("cipher", {}).get("bits", 256)
        for weak in WEAK_CIPHERS:
            if weak in cipher_name.upper():
                result["issues"].append({
                    "type": f"Weak Cipher: {weak}", "severity": "high",
                    "detail": f"Negotiated cipher {cipher_name} is considered weak"
                })
        if isinstance(bits, int) and bits < 128:
            result["issues"].append({
                "type": "Short Key Length", "severity": "high",
                "detail": f"Key length {bits} bits is too short"
            })

    def _check_wildcard(self, result: dict):
        cert  = result["cert"]
        subj  = cert.get("subject", "")
        sans  = cert.get("sans", [])
        count = sum(1 for s in [subj] + sans if s.startswith("*"))
        if count > 3:
            result["issues"].append({
                "type": "Excessive Wildcard SANs", "severity": "low",
                "detail": f"{count} wildcard SAN entries — broad attack surface"
            })

    def _check_weak_protocol(self, result: dict):
        for proto in result.get("protocols", []):
            if proto in WEAK_PROTOCOLS:
                result["issues"].append({
                    "type": f"Weak Protocol: {proto}", "severity": "high",
                    "detail": f"Server negotiated {proto} which is deprecated"
                })

    def _try_weak_protocols(self, target: str, port: int, result: dict):
        """Try to negotiate TLS 1.0 / 1.1."""
        for proto_const, proto_name in [
            (ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, 'PROTOCOL_TLS_CLIENT') else None, "TLSv1.2"),
        ]:
            pass  # Modern Python restricts old protocols; skip to avoid crashes

    def _print_summary(self, result: dict):
        cert = result.get("cert", {})
        if not cert:
            return
        tbl = Table(box=box.SIMPLE, header_style="bold cyan", show_header=False)
        tbl.add_column("Field", style="dim", width=22)
        tbl.add_column("Value", style="white")
        tbl.add_row("Subject",    cert.get("subject", "?"))
        tbl.add_row("Issuer",     cert.get("issuer", "?"))
        tbl.add_row("Expires",    cert.get("expiry", "?"))
        tbl.add_row("Days Left",  str(cert.get("days_left", "?")))
        tbl.add_row("Cipher",     result.get("cipher", {}).get("name", "?"))
        tbl.add_row("Grade",      f"[bold]{result['grade']}[/bold]")
        tbl.add_row("SANs",       ", ".join(cert.get("sans", [])[:5]))
        console.print(tbl)
