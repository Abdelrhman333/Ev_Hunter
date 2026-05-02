"""
EVHunter — AI Client  v2.1
OpenAI-compatible. Multi-agent system with retry, deterministic caching,
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

Fixes v2.1:
  - max_completion_tokens → max_tokens (Gemini + broader compatibility)
  - Added Gemini / Google AI URLs to no-JSON-mode list
  - Moved misplaced `import re, json` out of class body
  - Improved _parse_json to strip more wrapping variants
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
        "You are a senior recon analyst. Given compact scan data, identify "
        "interesting attack surface, suspicious services, and potential vulnerability classes. "
        "Return ONLY valid JSON: "
        "{\"findings\":[{\"type\":str,\"detail\":str,\"severity\":str,\"confidence\":int}],"
        "\"summary\":str}. "
        "Severity values: critical/high/medium/low/info. Confidence 0-100."
    ),
    "vuln": (
        "You are a vulnerability analyst. Given preprocessed target data, identify "
        "specific, exploitable vulnerabilities. Return ONLY valid JSON: "
        "{\"vulns\":[{\"title\":str,\"cve_hint\":str,\"severity\":str,\"affected\":str,"
        "\"reasoning\":str,\"curl_verify\":str,\"remediation\":str}],\"summary\":str}. "
        "curl_verify must be a real, executable curl command."
    ),
    "verifier": (
        "You are an exploit verifier. Given a curl HTTP response, determine if the "
        "vulnerability is confirmed. Return ONLY valid JSON: "
        "{\"confirmed\":bool,\"confidence\":int,\"evidence\":str,"
        "\"poc\":str,\"false_positive_reason\":str}. "
        "confidence is 0-100."
    ),
    "reporter": (
        "You are a professional security report writer. Given finding data, produce a "
        "detailed vulnerability report section. Return ONLY valid JSON: "
        "{\"title\":str,\"severity\":str,\"cvss_estimate\":str,\"description\":str,"
        "\"impact\":str,\"steps_to_reproduce\":str,\"curl_poc\":str,\"remediation\":str,"
        "\"references\":[str]}."
    ),
    "subdomain": (
        "You are a bug bounty analyst. Flag subdomains hinting at sensitive services "
        "(staging, admin, internal, jenkins, grafana, kibana, jira, gitlab, etc.). "
        "Return ONLY valid JSON: {\"flagged\":[{\"subdomain\":str,\"reason\":str,\"severity\":str}]}."
    ),
    "dns": (
        "You are a DNS security analyst. Analyze DNS records for security issues "
        "(SPF/DMARC misconfigs, dangling CNAMEs, zone transfer exposure, internal hostnames leaked). "
        "Return ONLY valid JSON: "
        "{\"issues\":[{\"type\":str,\"record\":str,\"detail\":str,\"severity\":str}],\"summary\":str}."
    ),
    "ssl": (
        "You are a TLS/SSL security expert. Analyze certificate and cipher data for weaknesses "
        "(expired certs, weak ciphers, missing HSTS, self-signed, wildcard abuse, etc.). "
        "Return ONLY valid JSON: "
        "{\"issues\":[{\"type\":str,\"detail\":str,\"severity\":str}],\"grade\":str,\"summary\":str}."
    ),
    "cors": (
        "You are a web security analyst specializing in CORS. Evaluate CORS headers for "
        "misconfigurations (wildcard origins, null origin, credentials+wildcard, etc.). "
        "Return ONLY valid JSON: "
        "{\"vulnerable\":bool,\"issues\":[{\"header\":str,\"value\":str,\"detail\":str,\"severity\":str}],"
        "\"summary\":str}."
    ),
    "secret": (
        "You are a secrets detection analyst. Given response snippets, identify exposed secrets, "
        "tokens, API keys, passwords, or PII patterns. "
        "Return ONLY valid JSON: "
        "{\"secrets\":[{\"type\":str,\"pattern\":str,\"context\":str,\"severity\":str}],\"summary\":str}."
    ),
    "js": (
        "You are a JavaScript security analyst. Given JS code snippets and found strings, "
        "extract and flag: API endpoints, hardcoded credentials, internal URLs, GraphQL queries, "
        "cloud storage buckets, JWT secrets. "
        "Return ONLY valid JSON: "
        "{\"endpoints\":[str],\"secrets\":[{\"type\":str,\"value\":str,\"severity\":str}],"
        "\"interesting\":[str],\"summary\":str}."
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
    # Gemini / Google AI variants
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
        # Detect provider capabilities once at init
        self._json_mode = self._probe_json_mode()

    def _probe_json_mode(self) -> bool:
        """Return True only if this provider supports response_format=json_object."""
        url_lower   = self.api_url.lower()
        model_lower = self.model.lower()
        for marker in _NO_JSON_MODE_PROVIDERS:
            if marker in url_lower or marker in model_lower:
                return False
        return True

    def _cache_key(self, system: str, payload: dict) -> str:
        """Deterministic SHA256-based cache key."""
        raw = system + json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def _call(self, system: str, user_payload: dict,
              max_tokens: int = 800) -> Optional[dict]:
        """
        Make an AI API call with retry and fallback JSON extraction.
        Returns parsed dict or None on failure.
        """
        user_msg  = json.dumps(user_payload, separators=(",", ":"))
        cache_key = self._cache_key(system, user_payload)

        if cache_key in self._cache:
            return self._cache[cache_key]

        # FIX: use max_tokens (universally supported) instead of max_completion_tokens
        body_dict: dict = {
            "model":       self.model,
            "max_tokens":  max_tokens,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user_msg},
            ],
        }
        # Only add response_format for providers that support it
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
                with urllib.request.urlopen(req, timeout=60) as resp:
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
                        # Show first 300 chars to help diagnose truncation vs bad format
                        preview = text[:300].replace("\n", " ")
                        console.print(f"  [dim]  Raw response: {preview}[/dim]")
                        if len(text) >= max_tokens * 3:  # rough char estimate
                            console.print(
                                "  [dim]  Response may be truncated — max_tokens too low[/dim]"
                            )
            except urllib.error.HTTPError as e:
                body_err = e.read().decode()[:300]
                console.print(f"  [red]  AI HTTP {e.code} (attempt {attempt}): {body_err}[/red]")
                if e.code in (401, 403):
                    return None
                if e.code == 429:
                    # Rate limit — wait much longer before retrying
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
        Parse JSON from AI response, handling:
          - Bare JSON objects/arrays
          - ```json ... ``` fences
          - ``` ... ``` fences (no language tag)
          - Leading/trailing prose before/after the JSON
        """
        if not text:
            return None

        text = text.strip()

        # Strip markdown code fences (with or without language tag)
        if text.startswith("```"):
            lines = text.splitlines()
            # Drop the opening fence line (```json or ```)
            inner = lines[1:] if len(lines) > 1 else lines
            # Drop closing fence if present
            if inner and inner[-1].strip() == "```":
                inner = inner[:-1]
            text = "\n".join(inner).strip()

        # Fast path: direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Extract first balanced JSON object or array using a char-by-char scanner
        start       = -1
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
                    candidate = text[start : i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        # Reset and keep searching
                        start = brace_cnt = bracket_cnt = 0

        return None

    # ── Public Agent Methods ───────────────────────────────────────────────────

    def analyze_recon(self, nmap_summary: dict, subdomains: list[str]) -> Optional[dict]:
        payload = {"nmap": nmap_summary, "subdomains_sample": subdomains[:30]}
        return self._call(AGENTS["recon"], payload, max_tokens=2000)

    def analyze_vulns(self, target: str, tech_stack: list, endpoints: list,
                      nuclei_hits: list, headers: dict) -> Optional[dict]:
        payload = {
            "target":      target,
            "tech":        tech_stack[:12],
            "endpoints":   endpoints[:25],
            "nuclei_hits": nuclei_hits[:15],
            "headers":     dict(list(headers.items())[:10]),
        }
        return self._call(AGENTS["vuln"], payload, max_tokens=3000)

    def verify_finding(self, vuln_title: str, curl_response: str,
                       status_code: int, response_time_ms: int) -> Optional[dict]:
        payload = {
            "vuln":         vuln_title,
            "status":       status_code,
            "resp_time_ms": response_time_ms,
            "body_snippet": curl_response[:500],
        }
        return self._call(AGENTS["verifier"], payload, max_tokens=1000)

    def write_report(self, finding: dict) -> Optional[dict]:
        return self._call(AGENTS["reporter"], finding, max_tokens=2000)

    def analyze_subdomains(self, subdomains: list[str]) -> Optional[dict]:
        return self._call(AGENTS["subdomain"], {"subdomains": subdomains[:60]}, max_tokens=2000)

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
        return self._call(AGENTS["js"], js_data, max_tokens=2000)

    def test_connection(self) -> bool:
        result = self._call(
            'Reply ONLY with this exact JSON: {"ok":true}',
            {"ping": 1}, max_tokens=20
        )
        return result is not None and result.get("ok") is True
