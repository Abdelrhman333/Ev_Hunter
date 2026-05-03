"""
EVHunter — GraphQL Security Tester  v1.0
Probes GraphQL endpoints for common misconfigurations and vulnerabilities.

Tests:
  - Introspection enabled (full schema leak)
  - Batch query attack (rate limit bypass)
  - Field suggestion enumeration (even without introspection)
  - Deeply nested query (DoS potential)
  - Missing authentication on queries/mutations
  - SQL / NoSQL injection via GraphQL arguments
  - Alias-based query abuse (bypass rate limits)
  - Debug / verbose error messages
"""

import json
import re
import urllib.error
import urllib.request
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from .base import ScannerModule

console = Console()

# Known GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/gql",
    "/api/gql", "/v1/graphql", "/v2/graphql",
    "/playground", "/graphql/console", "/graphql/explorer",
    "/api/v1/graphql", "/api/v2/graphql",
    "/graphql/v1", "/graphql/v2",
]

# Introspection query
INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields {
        name
        type { name kind }
        args { name type { name kind } }
      }
    }
  }
}
"""

# Minimal introspection (less likely to be blocked)
MINI_INTROSPECTION = "{ __schema { types { name } } }"

# Field suggestion probe — sends invalid field to trigger "did you mean X?" error
FIELD_SUGGESTION = "{ invalidFieldThatDoesNotExist123 }"

# Batch query
BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

# Deeply nested query (DoS test)
DEEPLY_NESTED = "{ a { b { c { d { e { f { g { __typename } } } } } } } }"

# Common mutations that may be unauthenticated
AUTH_BYPASS_QUERIES = [
    {"query": "mutation { login(username: \"admin\", password: \"admin\") { token } }"},
    {"query": "mutation { register(email: \"test@evil.com\", password: \"test123\") { id } }"},
    {"query": "{ users { id email password } }"},
    {"query": "{ user(id: 1) { email password apiKey token } }"},
    {"query": "{ me { id email role permissions } }"},
    {"query": "{ admin { users { id email password role } } }"},
    {"query": "{ allUsers { id email password createdAt } }"},
]

# IDOR via argument manipulation
IDOR_QUERIES = [
    {"query": "{ user(id: 1) { id email } }"},
    {"query": "{ user(id: 2) { id email } }"},
    {"query": "{ order(id: 1) { id total user { email } } }"},
]

# NoSQL/SQLi via GraphQL arguments
INJECTION_QUERIES = [
    {"query": '{ users(filter: "1\' OR \'1\'=\'1") { id email } }'},
    {"query": '{ users(id: "1 OR 1=1") { id email } }'},
    {"query": '{ user(username: {$gt: ""}) { id email } }'},
]


class GraphQLTesterModule(ScannerModule):
    name        = "graphql"
    description = "GraphQL security testing — introspection, batch, IDOR, injection"

    def run(
        self,
        target: str,
        alive_hosts: list[dict] = None,
        js_endpoints: list[str] = None,
        **kwargs,
    ) -> dict[str, Any]:
        self._start_timer()
        self._status(f"GraphQL testing on [cyan]{target}[/cyan]…")

        base_url = target if target.startswith("http") else f"https://{target}"

        result: dict[str, Any] = {
            "ok":                    True,
            "target":                target,
            "graphql_endpoints":     [],
            "introspection_enabled": False,
            "schema":                {},
            "vulnerabilities":       [],
            "sensitive_types":       [],
            "summary":               "",
        }

        # ── 1. Discover GraphQL endpoints ─────────────────────────────────────
        candidate_urls = self._discover_endpoints(base_url, js_endpoints or [])
        result["graphql_endpoints"] = candidate_urls

        if not candidate_urls:
            result["summary"] = "No GraphQL endpoints discovered"
            self._ok(f"GraphQL done — no endpoints found [{self._elapsed()}]")
            return result

        # ── 2. Test each endpoint ─────────────────────────────────────────────
        for gql_url in candidate_urls[:5]:
            console.print(f"  [dim]  Testing GraphQL endpoint: {gql_url}[/dim]")
            self._test_endpoint(gql_url, result)

        total = len(result["vulnerabilities"])
        color = "red" if total > 0 else "green"
        result["summary"] = (
            f"Found {total} GraphQL vulnerability(ies) across "
            f"{len(candidate_urls)} endpoint(s)"
            if total else "No critical GraphQL vulnerabilities found"
        )

        self._ok(
            f"GraphQL done — {len(candidate_urls)} endpoint(s), "
            f"[bold {color}]{total}[/bold {color}] issue(s) [{self._elapsed()}]"
        )
        self._print_table(result)
        return result

    # ── Endpoint discovery ────────────────────────────────────────────────────

    def _discover_endpoints(self, base_url: str, js_endpoints: list[str]) -> list[str]:
        found = []

        # 1. Probe known paths
        for path in GRAPHQL_PATHS:
            url = base_url.rstrip("/") + path
            if self._is_graphql(url):
                found.append(url)

        # 2. Check JS-extracted endpoints
        for ep in js_endpoints:
            if any(gql_hint in ep.lower() for gql_hint in ("graphql", "gql", "playground")):
                if not ep.startswith("http"):
                    ep = base_url.rstrip("/") + ep
                if ep not in found and self._is_graphql(ep):
                    found.append(ep)

        if found:
            console.print(f"  [green]  ✔ Found {len(found)} GraphQL endpoint(s)[/green]")
        else:
            console.print("  [dim]  No GraphQL endpoints found[/dim]")

        return found

    def _is_graphql(self, url: str) -> bool:
        """Send a minimal query to check if endpoint is GraphQL."""
        resp = self._gql_request(url, {"query": "{ __typename }"})
        if not resp:
            return False
        # GraphQL responses always have "data" or "errors"
        return "data" in resp or "errors" in resp

    # ── Vulnerability tests ───────────────────────────────────────────────────

    def _test_endpoint(self, url: str, result: dict):
        # Test 1: Introspection
        self._test_introspection(url, result)

        # Test 2: Field suggestions (even without introspection)
        self._test_field_suggestions(url, result)

        # Test 3: Batch query attack
        self._test_batch_queries(url, result)

        # Test 4: Deep nesting DoS
        self._test_deep_nesting(url, result)

        # Test 5: Unauthenticated sensitive queries
        self._test_auth_bypass(url, result)

        # Test 6: IDOR via argument manipulation
        self._test_idor(url, result)

        # Test 7: Injection
        self._test_injection(url, result)

        # Test 8: Aliases
        self._test_alias_abuse(url, result)

    def _test_introspection(self, url: str, result: dict):
        resp = self._gql_request(url, {"query": INTROSPECTION_QUERY})
        if not resp:
            return

        if "data" in resp and resp["data"] and "__schema" in resp.get("data", {}):
            schema = resp["data"]["__schema"]
            result["introspection_enabled"] = True
            result["schema"] = schema

            # Extract sensitive type names
            types = schema.get("types", [])
            sensitive_keywords = [
                "password", "secret", "token", "key", "auth", "credential",
                "payment", "card", "ssn", "private", "internal", "admin",
                "debug", "config", "setting",
            ]
            sensitive_types = []
            all_fields = []

            for t in types:
                if not t.get("name") or t["name"].startswith("__"):
                    continue
                type_name = t["name"].lower()
                fields = t.get("fields") or []

                for f in fields:
                    fname = f.get("name", "")
                    all_fields.append(f"{t['name']}.{fname}")
                    if any(kw in fname.lower() for kw in sensitive_keywords):
                        sensitive_types.append(f"{t['name']}.{fname}")

            result["sensitive_types"] = sensitive_types[:30]

            vuln = {
                "type":      "Introspection Enabled",
                "url":       url,
                "severity":  "medium",
                "detail":    (
                    f"Full schema exposed: {len(types)} types, "
                    f"{len(all_fields)} fields. "
                    f"Sensitive fields found: {len(sensitive_types)}"
                ),
                "query_poc": MINI_INTROSPECTION,
            }
            result["vulnerabilities"].append(vuln)
            console.print(
                f"  [yellow]  ⚠ Introspection enabled — "
                f"{len(types)} types, {len(sensitive_types)} sensitive fields[/yellow]"
            )

            if sensitive_types:
                console.print(
                    f"  [red]  ⚡ Sensitive fields: {', '.join(sensitive_types[:5])}[/red]"
                )

    def _test_field_suggestions(self, url: str, result: dict):
        resp = self._gql_request(url, {"query": FIELD_SUGGESTION})
        if not resp:
            return

        errors = resp.get("errors", [])
        for err in errors:
            msg = err.get("message", "")
            # GraphQL field suggestion pattern: "Did you mean 'fieldName'?"
            suggestions = re.findall(r"""[Dd]id you mean ['"]([\w]+)['"]""", msg)
            if suggestions:
                result["vulnerabilities"].append({
                    "type":      "Field Suggestion Enumeration",
                    "url":       url,
                    "severity":  "low",
                    "detail":    (
                        f"Server reveals field names via suggestions: "
                        f"{', '.join(suggestions)}"
                    ),
                    "query_poc": FIELD_SUGGESTION,
                })
                console.print(
                    f"  [cyan]  ℹ Field suggestions: {', '.join(suggestions)}[/cyan]"
                )
                break

    def _test_batch_queries(self, url: str, result: dict):
        """Test if batch queries work — can bypass rate limiting."""
        resp_raw = self._gql_request_raw(url, BATCH_QUERY)
        if not resp_raw:
            return

        if isinstance(resp_raw, list) and len(resp_raw) > 1:
            result["vulnerabilities"].append({
                "type":      "Batch Query Enabled",
                "url":       url,
                "severity":  "medium",
                "detail":    (
                    f"GraphQL batch queries accepted — attacker can send "
                    f"N queries in a single request, bypassing per-request rate limits"
                ),
                "query_poc": json.dumps(BATCH_QUERY[:2]),
            })
            console.print("  [yellow]  ⚠ Batch queries enabled — rate limit bypass possible[/yellow]")

    def _test_deep_nesting(self, url: str, result: dict):
        """Send deeply nested query — possible DoS."""
        # Build a 20-level deep query on __typename (safe)
        depth = 15
        query = "{ " + " { ".join(["__typename"] * 1) + " { " * (depth - 1)
        query += "__typename" + " } " * depth + " }"

        resp = self._gql_request(url, {"query": DEEPLY_NESTED})
        if not resp:
            return

        # If it doesn't error or time out, it's potentially vulnerable to DoS
        if "data" in resp or "errors" in resp:
            result["vulnerabilities"].append({
                "type":      "Unrestricted Query Depth",
                "url":       url,
                "severity":  "low",
                "detail":    "No query depth limit enforced — deeply nested queries accepted",
                "query_poc": DEEPLY_NESTED,
            })

    def _test_auth_bypass(self, url: str, result: dict):
        """Test sensitive queries without authentication."""
        for query_dict in AUTH_BYPASS_QUERIES:
            resp = self._gql_request(url, query_dict)
            if not resp:
                continue

            data = resp.get("data", {})
            errors = resp.get("errors", [])

            # If data is returned (not null/empty) without auth error
            if data and any(v is not None for v in data.values()):
                # Check if sensitive data is returned
                data_str = json.dumps(data).lower()
                if any(kw in data_str for kw in ("email", "password", "token", "id")):
                    result["vulnerabilities"].append({
                        "type":      "Unauthenticated Sensitive Query",
                        "url":       url,
                        "severity":  "high",
                        "detail":    f"Sensitive data returned without authentication: {str(data)[:200]}",
                        "query_poc": query_dict["query"],
                    })
                    console.print(
                        f"  [red]  ⚡ HIGH: Unauthenticated query returned data![/red]"
                    )

            # Check for overly verbose errors (info leak)
            for err in errors:
                msg = err.get("message", "")
                if any(kw in msg.lower() for kw in
                       ("sql", "syntax", "exception", "stacktrace", "undefined method")):
                    result["vulnerabilities"].append({
                        "type":      "Verbose Error Information Leak",
                        "url":       url,
                        "severity":  "medium",
                        "detail":    f"Verbose error message: {msg[:200]}",
                        "query_poc": query_dict["query"],
                    })

    def _test_idor(self, url: str, result: dict):
        """Test object-level authorization."""
        responses = []
        for query_dict in IDOR_QUERIES:
            resp = self._gql_request(url, query_dict)
            if resp and "data" in resp and resp["data"]:
                data_str = json.dumps(resp["data"])
                if len(data_str) > 10:  # Non-null response
                    responses.append((query_dict["query"], resp["data"]))

        if len(responses) >= 2:
            result["vulnerabilities"].append({
                "type":      "Potential IDOR via Object ID",
                "url":       url,
                "severity":  "high",
                "detail":    f"Multiple objects returned by ID — verify authorization checks",
                "query_poc": IDOR_QUERIES[0]["query"],
            })

    def _test_injection(self, url: str, result: dict):
        """Test for SQL/NoSQL injection via GraphQL arguments."""
        for query_dict in INJECTION_QUERIES:
            resp = self._gql_request(url, query_dict)
            if not resp:
                continue

            errors = resp.get("errors", [])
            resp_str = json.dumps(resp).lower()

            # SQL injection indicators
            sql_indicators = [
                "syntax error", "sql error", "mysql_error", "pg_query",
                "sqlite3", "ora-0", "odbc_", "near \"", "unclosed quotation",
            ]
            for indicator in sql_indicators:
                if indicator in resp_str:
                    result["vulnerabilities"].append({
                        "type":      "GraphQL SQL Injection",
                        "url":       url,
                        "severity":  "critical",
                        "detail":    f"SQL error triggered: {indicator}",
                        "query_poc": query_dict["query"],
                    })
                    break

    def _test_alias_abuse(self, url: str, result: dict):
        """Test alias-based query to bypass rate limits or brute force."""
        alias_query = {
            "query": """
            {
              a1: __typename
              a2: __typename
              a3: __typename
              a4: __typename
              a5: __typename
            }
            """
        }
        resp = self._gql_request(url, alias_query)
        if resp and resp.get("data"):
            data = resp["data"]
            if all(f"a{i}" in data for i in range(1, 6)):
                result["vulnerabilities"].append({
                    "type":      "Alias Abuse (Query Multiplication)",
                    "url":       url,
                    "severity":  "low",
                    "detail":    "Aliases allow N operations per request, bypassing per-operation rate limits",
                    "query_poc": alias_query["query"].strip(),
                })

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _gql_request(self, url: str, payload: dict) -> Optional[dict]:
        body = json.dumps(payload).encode()
        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent":   "EVHunter/3.0",
                    "Accept":       "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read())
            except Exception:
                return None
        except Exception:
            return None

    def _gql_request_raw(self, url: str, payload) -> Optional[Any]:
        """For batch requests — returns raw parsed JSON (list or dict)."""
        body = json.dumps(payload).encode()
        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent":   "EVHunter/3.0",
                    "Accept":       "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    # ── Display ───────────────────────────────────────────────────────────────

    def _print_table(self, result: dict):
        vulns = result["vulnerabilities"]
        if not vulns:
            return

        console.print()
        tbl = Table(
            title=f"  [bold]GraphQL Findings ({len(vulns)})[/bold]",
            box=box.SIMPLE_HEAVY, header_style="bold cyan", border_style="yellow",
        )
        tbl.add_column("Severity", width=10)
        tbl.add_column("Type",     max_width=35)
        tbl.add_column("URL",      max_width=45, style="dim")
        SEV = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        for v in vulns:
            sev = v.get("severity", "low")
            tbl.add_row(
                f"[{SEV.get(sev,'white')}]{sev.upper()}[/{SEV.get(sev,'white')}]",
                v.get("type", "?")[:35],
                v.get("url", "?")[:45],
            )
        console.print(tbl)

        if result["sensitive_types"]:
            console.print(
                f"  [yellow]  ⚠ Sensitive schema fields: "
                f"{', '.join(result['sensitive_types'][:8])}[/yellow]"
            )
