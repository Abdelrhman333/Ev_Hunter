"""
BugHunter - AI Client
OpenAI-compatible. Sends compact, preprocessed payloads to minimize token usage.
Multi-agent system: ReconAnalyst | VulnAnalyst | ExploitVerifier | ReportWriter
"""

import json
import time
import urllib.request
import urllib.error
from typing import Optional

from rich.console import Console

console = Console()

# ── Agent System Prompts (kept very short to save tokens) ─────────────────────

AGENTS = {
    "recon": (
        "You are a senior recon analyst. Given compact scan data, identify "
        "interesting attack surface, suspicious services, and potential vuln classes. "
        "Return JSON: {findings:[{type,detail,severity,confidence}], summary:str}. "
        "Be concise. Severity: critical/high/medium/low/info."
    ),
    "vuln": (
        "You are a vulnerability analyst. Given preprocessed target data, identify "
        "specific vulnerabilities. Return JSON: "
        "{vulns:[{title,cve_hint,severity,affected,reasoning,curl_verify}], summary:str}. "
        "curl_verify must be a real curl command to confirm the vuln."
    ),
    "verifier": (
        "You are an exploit verifier. Given a curl response, decide if the "
        "vulnerability is confirmed. Return JSON: "
        "{confirmed:bool,confidence:int,evidence:str,poc:str,false_positive_reason:str}."
    ),
    "reporter": (
        "You are a security report writer. Given finding data, write a professional "
        "vulnerability report section. Return JSON: "
        "{title,severity,cvss_estimate,description,impact,steps_to_reproduce,curl_poc,remediation}."
    ),
}

# ── Severity color map ─────────────────────────────────────────────────────────
SEV_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}


class AIClient:
    def __init__(self, api_url: str, api_key: str, model: str):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.model   = model
        self._cache: dict = {}

    def _call(self, system: str, user_payload: dict, max_tokens: int = 800) -> Optional[dict]:
        """
        Make a single API call. Returns parsed JSON or None on error.
        Payload is always a compact JSON string to minimize tokens.
        """
        user_msg = json.dumps(user_payload, separators=(",", ":"))

        cache_key = hash(system + user_msg)
        if cache_key in self._cache:
            return self._cache[cache_key]

        body = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user_msg},
            ],
            "response_format": {"type": "json_object"},
        }).encode()

        req = urllib.request.Request(
            f"{self.api_url}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type":  "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
                text = data["choices"][0]["message"]["content"]
                result = json.loads(text)
                self._cache[cache_key] = result
                return result
        except urllib.error.HTTPError as e:
            console.print(f"[red]  AI API error {e.code}: {e.read().decode()[:200]}[/red]")
        except Exception as e:
            console.print(f"[red]  AI call failed: {e}[/red]")
        return None

    # ── Public agent methods ───────────────────────────────────────────────────

    def analyze_recon(self, nmap_summary: dict, subdomains: list[str]) -> Optional[dict]:
        """ReconAnalyst — identify attack surface from compact nmap + subdomain data."""
        payload = {
            "nmap": nmap_summary,
            "subdomains_sample": subdomains[:30],  # cap to save tokens
        }
        return self._call(AGENTS["recon"], payload, max_tokens=600)

    def analyze_vulns(self, target: str, tech_stack: list, endpoints: list,
                      nuclei_hits: list, headers: dict) -> Optional[dict]:
        """VulnAnalyst — identify specific vulnerabilities."""
        payload = {
            "target":      target,
            "tech":        tech_stack[:10],
            "endpoints":   endpoints[:20],
            "nuclei_hits": nuclei_hits[:15],
            "headers":     {k: v for k, v in list(headers.items())[:8]},
        }
        return self._call(AGENTS["vuln"], payload, max_tokens=900)

    def verify_finding(self, vuln_title: str, curl_response: str,
                       status_code: int, response_time_ms: int) -> Optional[dict]:
        """ExploitVerifier — confirm if curl response proves the vulnerability."""
        payload = {
            "vuln":        vuln_title,
            "status":      status_code,
            "resp_time_ms": response_time_ms,
            "body_snippet": curl_response[:400],  # only a snippet
        }
        return self._call(AGENTS["verifier"], payload, max_tokens=500)

    def write_report(self, finding: dict) -> Optional[dict]:
        """ReportWriter — generate a professional vuln report section."""
        return self._call(AGENTS["reporter"], finding, max_tokens=700)

    def analyze_subdomains(self, subdomains: list[str]) -> Optional[dict]:
        """Quick AI pass to flag sensitive-looking subdomains."""
        system = (
            "You are a bug bounty analyst. Flag subdomains that hint at sensitive "
            "services (staging, admin, internal, jenkins, grafana, etc.). "
            "Return JSON: {flagged:[{subdomain,reason,severity}]}."
        )
        payload = {"subdomains": subdomains[:50]}
        return self._call(system, payload, max_tokens=500)

    def test_connection(self) -> bool:
        """Quick connectivity test."""
        result = self._call("Reply only with: {\"ok\":true}", {"ping": 1}, max_tokens=10)
        return result is not None
