"""
EVHunter — AI Client  v3.0
OpenAI-compatible. Multi-agent with retry, deterministic caching,
and graceful fallback for providers that don't support json_object mode.

Agents:
  recon      — attack surface identification from scan data
  vuln       — vulnerability identification from tech/endpoint data
  verifier   — curl response analysis & PoC confirmation
  reporter   — professional vulnerability report writing
  subdomain  — sensitive subdomain flagging
  dns        — DNS anomaly analysis
  ssl        — SSL/TLS weakness identification
  cors       — CORS policy evaluation
  secret     — secret/credential pattern analysis
  js         — JS endpoint and API key extraction analysis
  crawler    — crawl result analysis for hidden attack surface
  param      — parameter fuzzing result analysis
  header     — header injection result analysis
  graphql    — GraphQL schema/introspection analysis

Fixes v3.0:
  - CRITICAL: _parse_json reset bug fixed (start = -1, not 0)
  - Added new agents for new modules
  - Better token budgets per agent
  - Improved system prompts for higher-quality findings
  - Added streaming-safe response handling
"""

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from rich.console import Console

console = Console()

# ── Agent System Prompts ──────────────────────────────────────────────────────

AGENTS: dict[str, str] = {
    "recon": (
        "You are a senior penetration tester. Given compact nmap scan data, identify "
        "attack surface, suspicious services, misconfigurations, and vulnerability classes. "
        "Focus on: unusual ports, default credentials risk, unencrypted services, "
        "version-specific CVEs. "
        "Return ONLY valid JSON: "
        '{"findings":[{"type":str,"detail":str,"severity":str,"confidence":int,"cve_hint":str}],'
        '"summary":str}. '
        "Severity: critical/high/medium/low/info. Confidence 0-100."
    ),
    "vuln": (
        "You are an expert bug bounty hunter. Given preprocessed target data (tech stack, "
        "endpoints, headers, nuclei hits), identify SPECIFIC exploitable vulnerabilities. "
        "Prioritize: SSRF, SQLi, XSS, IDOR, auth bypass, misconfigurations, exposed admin panels. "
        "Each curl_verify MUST be a real, complete, executable curl command that a human could run. "
        "Return ONLY valid JSON: "
        '{"vulns":[{"title":str,"cve_hint":str,"severity":str,"affected":str,'
        '"reasoning":str,"curl_verify":str,"remediation":str}],"summary":str}. '
    ),
    "verifier": (
        "You are an exploit verifier. Given a curl HTTP response, determine if the "
        "vulnerability is confirmed. Analyze: status codes, response body, headers, timing. "
        "Return ONLY valid JSON: "
        '{"confirmed":bool,"confidence":int,"evidence":str,'
        '"poc":str,"false_positive_reason":str}. '
        "confidence is 0-100."
    ),
    "reporter": (
        "You are a senior security researcher writing a professional bug bounty report. "
        "Given finding data, produce a detailed, actionable vulnerability report. "
        "Include business impact, CVSS scoring rationale, and step-by-step reproduction. "
        "Return ONLY valid JSON: "
        '{"title":str,"severity":str,"cvss_estimate":str,"description":str,'
        '"impact":str,"steps_to_reproduce":str,"curl_poc":str,"remediation":str,'
        '"references":[str]}.'
    ),
    "subdomain": (
        "You are a bug bounty recon specialist. Flag subdomains hinting at sensitive services "
        "(staging, admin, internal, jenkins, grafana, kibana, jira, gitlab, dev, test, uat, "
        "api, legacy, backup, db, vpn, mail, ftp, s3, cdn). "
        "Return ONLY valid JSON: "
        '{"flagged":[{"subdomain":str,"reason":str,"severity":str,"attack_vectors":[str]}]}.'
    ),
    "dns": (
        "You are a DNS security analyst. Analyze DNS records for: SPF/DMARC misconfigs, "
        "dangling CNAMEs (subdomain takeover), zone transfer exposure, internal hostnames, "
        "email security gaps, wildcard DNS abuse. "
        "Return ONLY valid JSON: "
        '{"issues":[{"type":str,"record":str,"detail":str,"severity":str,'
        '"takeover_candidate":bool}],"summary":str}.'
    ),
    "ssl": (
        "You are a TLS/SSL expert. Analyze certificate and cipher data for: "
        "expired/expiring certs, weak ciphers (RC4, 3DES, EXPORT), missing HSTS, "
        "self-signed certs, wildcard abuse, weak key sizes, protocol downgrade risks. "
        "Return ONLY valid JSON: "
        '{"issues":[{"type":str,"detail":str,"severity":str,"exploitable":bool}],'
        '"grade":str,"summary":str}.'
    ),
    "cors": (
        "You are a web security analyst specializing in CORS. Evaluate CORS headers for "
        "misconfigurations: wildcard origins, null origin, credentials+wildcard, "
        "arbitrary origin reflection, subdomain bypass. "
        "Return ONLY valid JSON: "
        '{"vulnerable":bool,"issues":[{"header":str,"value":str,"detail":str,"severity":str,'
        '"exploit_scenario":str}],"summary":str}.'
    ),
    "secret": (
        "You are a secrets detection analyst. Given response snippets, identify exposed: "
        "API keys, tokens, passwords, PII, private keys, cloud credentials, JWT secrets. "
        "Assess exploitability of each. "
        "Return ONLY valid JSON: "
        '{"secrets":[{"type":str,"pattern":str,"context":str,"severity":str,"exploitable":bool}],'
        '"summary":str}.'
    ),
    "js": (
        "You are a JavaScript security analyst. Given JS code snippets and found strings, "
        "extract and flag: API endpoints, hardcoded credentials, internal URLs, GraphQL "
        "queries, cloud storage buckets, JWT secrets, debug endpoints, admin routes. "
        "Return ONLY valid JSON: "
        '{"endpoints":[str],"secrets":[{"type":str,"value":str,"severity":str}],'
        '"interesting":[str],"graphql_found":bool,"summary":str}.'
    ),
    "crawler": (
        "You are a web app pentester. Given crawl results (pages, forms, endpoints, "
        "interesting paths), identify attack surface and prioritize for testing. "
        "Flag: login forms, file uploads, search inputs, admin panels, API endpoints, "
        "debug pages, backup files. "
        "Return ONLY valid JSON: "
        '{"high_value_targets":[{"url":str,"reason":str,"attack_type":str,"severity":str}],'
        '"attack_surface_summary":str}.'
    ),
    "param": (
        "You are a bug bounty hunter analyzing parameter discovery results. "
        "Given endpoints with discovered parameters and response differences, identify "
        "parameters that could be vulnerable to: SQLi, XSS, SSRF, path traversal, IDOR. "
        "Return ONLY valid JSON: "
        '{"interesting_params":[{"url":str,"param":str,"reason":str,"test_payload":str,'
        '"severity":str}],"summary":str}.'
    ),
    "header": (
        "You are a penetration tester analyzing HTTP header injection results. "
        "Given header injection test results, confirm: Host header injection, "
        "IP bypass via X-Forwarded-For, path bypass via X-Original-URL, "
        "cache poisoning potential. "
        "Return ONLY valid JSON: "
        '{"vulnerabilities":[{"type":str,"header":str,"value":str,"evidence":str,'
        '"severity":str,"curl_poc":str}],"summary":str}.'
    ),
    "graphql": (
        "You are a GraphQL security expert. Given GraphQL introspection data or responses, "
        "identify: exposed sensitive types/fields, missing auth on queries/mutations, "
        "batch query abuse potential, introspection enabled (info leak), field suggestions, "
        "deeply nested query DoS risk. "
        "Return ONLY valid JSON: "
        '{"issues":[{"type":str,"detail":str,"severity":str,"query_poc":str}],'
        '"introspection_enabled":bool,"sensitive_fields":[str],"summary":str}.'
    ),
    "open_redirect": (
        "You are a web security analyst. Given open redirect test results showing parameters "
        "and responses, confirm: open redirects, header-based redirects, meta refresh redirects. "
        "Assess phishing/OAuth token theft potential. "
        "Return ONLY valid JSON: "
        '{"redirects":[{"url":str,"param":str,"payload":str,"destination":str,'
        '"severity":str,"confirmed":bool}],"summary":str}.'
    ),
}

SEV_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}

# Providers / URL substrings that do NOT support response_format=json_object
_NO_JSON_MODE_PROVIDERS = [
    "ollama", "groq", "together", "localhost", "127.0.0.1",
    "generativelanguage.googleapis.com",
    "aistudio.google.com",
    "gemini",
    "google",
]


class AIClient:
    def __init__(self, api_url: str, api_key: str, model: str,
                 max_retries: int = 3, retry_delay: float = 2.0):
        self.api_url     = api_url.rstrip("/")
        self.api_key     = api_key
        self.model       = model
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._cache: dict[str, Any] = {}
        self._json_mode = self._probe_json_mode()

    def _probe_json_mode(self) -> bool:
        url_lower   = self.api_url.lower()
        model_lower = self.model.lower()
        for marker in _NO_JSON_MODE_PROVIDERS:
            if marker in url_lower or marker in model_lower:
                return False
        return True

    def _cache_key(self, system: str, payload: dict) -> str:
        raw = system + json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def _call(self, system: str, user_payload: dict,
              max_tokens: int = 800) -> Optional[dict]:
        user_msg  = json.dumps(user_payload, separators=(",", ":"))
        cache_key = self._cache_key(system, user_payload)

        if cache_key in self._cache:
            return self._cache[cache_key]

        body_dict: dict = {
            "model":       self.model,
            "max_tokens":  max_tokens,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user_msg},
            ],
        }
        if self._json_mode:
            body_dict["response_format"] = {"type": "json_object"}

        body = json.dumps(body_dict).encode()
        req  = urllib.request.Request(
            f"{self.api_url}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type":  "application/json",
            },
            method="POST",
        )

        for attempt in range(1, self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    data   = json.loads(resp.read())
                    text   = data["choices"][0]["message"]["content"]
                    result = self._parse_json(text)
                    if result is not None:
                        self._cache[cache_key] = result
                        return result
                    console.print(
                        f"  [yellow]  AI response not valid JSON (attempt {attempt})[/yellow]"
                    )
                    if attempt == self.max_retries:
                        preview = text[:300].replace("\n", " ")
                        console.print(f"  [dim]  Raw response: {preview}[/dim]")
            except urllib.error.HTTPError as e:
                body_err = e.read().decode()[:300]
                console.print(f"  [red]  AI HTTP {e.code} (attempt {attempt}): {body_err}[/red]")
                if e.code in (401, 403):
                    return None
                if e.code == 429:
                    wait = self.retry_delay * (attempt * 10)
                    console.print(f"  [yellow]  Rate limited — waiting {wait:.0f}s…[/yellow]")
                    time.sleep(wait)
                    continue
            except urllib.error.URLError as e:
                console.print(f"  [red]  AI connection error (attempt {attempt}): {e.reason}[/red]")
            except Exception as e:
                console.print(f"  [red]  AI call failed (attempt {attempt}): {e}[/red]")

            if attempt < self.max_retries:
                time.sleep(self.retry_delay * attempt)

        return None

    @staticmethod
    def _parse_json(text: str) -> Optional[dict]:
        """
        Robust JSON extractor. Handles all markdown fence styles + bare JSON.

        BUG FIX v3.0: Reset `start = -1` (not 0) when abandoning a candidate block,
        otherwise the scanner would start re-scanning from position 0 (beginning of
        string) instead of continuing forward, causing infinite loops on malformed
        JSON or missing the real JSON block entirely.
        """
        if not text:
            return None

        text = text.strip()

        # Strip markdown fences
        text = re.sub(r"```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"```", "", text)
        text = text.strip()

        # Fast-path: direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Char-by-char balanced-brace scanner
        start       = -1   # FIX: was 0, must be -1 (sentinel "not started")
        brace_cnt   = 0
        bracket_cnt = 0
        in_string   = False
        escaped     = False

        for i, ch in enumerate(text):
            if escaped:
                escaped = False
                continue
            if in_string:
                if ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
                continue
            if ch in "{[":
                if start == -1:
                    start = i
                if ch == "{":
                    brace_cnt += 1
                else:
                    bracket_cnt += 1
            elif ch in "}]":
                if ch == "}":
                    brace_cnt -= 1
                else:
                    bracket_cnt -= 1
                if start != -1 and brace_cnt == 0 and bracket_cnt == 0:
                    candidate = text[start: i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        # FIX: reset to -1 (sentinel), not 0 (position)
                        start = -1
                        brace_cnt = bracket_cnt = 0

        return None

    # ── Public Agent Methods ───────────────────────────────────────────────────

    def analyze_recon(self, nmap_summary: dict, subdomains: list[str]) -> Optional[dict]:
        payload = {"nmap": nmap_summary, "subdomains_sample": subdomains[:30]}
        return self._call(AGENTS["recon"], payload, max_tokens=2500)

    def analyze_vulns(self, target: str, tech_stack: list, endpoints: list,
                      nuclei_hits: list, headers: dict) -> Optional[dict]:
        payload = {
            "target":      target,
            "tech":        tech_stack[:15],
            "endpoints":   endpoints[:30],
            "nuclei_hits": nuclei_hits[:15],
            "headers":     dict(list(headers.items())[:15]),
        }
        return self._call(AGENTS["vuln"], payload, max_tokens=4000)

    def verify_finding(self, vuln_title: str, curl_response: str,
                       status_code: int, response_time_ms: int) -> Optional[dict]:
        payload = {
            "vuln":         vuln_title,
            "status":       status_code,
            "resp_time_ms": response_time_ms,
            "body_snippet": curl_response[:600],
        }
        return self._call(AGENTS["verifier"], payload, max_tokens=1200)

    def write_report(self, finding: dict) -> Optional[dict]:
        return self._call(AGENTS["reporter"], finding, max_tokens=2500)

    def analyze_subdomains(self, subdomains: list[str]) -> Optional[dict]:
        return self._call(AGENTS["subdomain"], {"subdomains": subdomains[:80]}, max_tokens=2500)

    def analyze_dns(self, dns_data: dict) -> Optional[dict]:
        return self._call(AGENTS["dns"], dns_data, max_tokens=2000)

    def analyze_ssl(self, ssl_data: dict) -> Optional[dict]:
        return self._call(AGENTS["ssl"], ssl_data, max_tokens=2000)

    def analyze_cors(self, cors_data: dict) -> Optional[dict]:
        return self._call(AGENTS["cors"], cors_data, max_tokens=1500)

    def analyze_secrets(self, snippets: list[dict]) -> Optional[dict]:
        payload = {"snippets": snippets[:20]}
        return self._call(AGENTS["secret"], payload, max_tokens=2000)

    def analyze_js(self, js_data: dict) -> Optional[dict]:
        return self._call(AGENTS["js"], js_data, max_tokens=2500)

    def analyze_crawler(self, crawl_data: dict) -> Optional[dict]:
        payload = {
            "interesting": crawl_data.get("interesting", [])[:30],
            "forms":       crawl_data.get("forms", [])[:20],
            "endpoints":   crawl_data.get("endpoints", [])[:25],
            "page_count":  len(crawl_data.get("pages", [])),
        }
        return self._call(AGENTS["crawler"], payload, max_tokens=2500)

    def analyze_params(self, param_data: dict) -> Optional[dict]:
        return self._call(AGENTS["param"], param_data, max_tokens=2000)

    def analyze_headers(self, header_data: dict) -> Optional[dict]:
        return self._call(AGENTS["header"], header_data, max_tokens=2000)

    def analyze_graphql(self, gql_data: dict) -> Optional[dict]:
        return self._call(AGENTS["graphql"], gql_data, max_tokens=3000)

    def analyze_open_redirect(self, redirect_data: dict) -> Optional[dict]:
        return self._call(AGENTS["open_redirect"], redirect_data, max_tokens=2000)

    def test_connection(self) -> bool:
        result = self._call(
            'Reply ONLY with this exact JSON: {"ok":true}',
            {"ping": 1}, max_tokens=20
        )
        return result is not None and result.get("ok") is True
