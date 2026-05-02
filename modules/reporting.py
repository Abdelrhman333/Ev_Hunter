"""
EVHunter — Report Generator  v2.0
Produces Markdown + HTML vulnerability reports.

Improvements vs original:
  - Uses the `markdown` library for proper MD→HTML conversion (no brittle regex)
  - Executive summary with risk score
  - Module-specific finding sections
  - JSON export
  - Timeline of scan events
"""

import json
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

console = Console()

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_CVSS  = {"critical": "9.0–10.0", "high": "7.0–8.9", "medium": "4.0–6.9",
              "low": "0.1–3.9", "info": "N/A"}


def _sev(f: dict) -> int:
    return SEV_ORDER.get((f.get("severity") or "info").lower(), 5)


def _risk_score(findings: list[dict]) -> tuple[int, str]:
    """Calculate an overall risk score 0–100 and label."""
    weights = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
    raw = sum(weights.get((f.get("severity") or "info").lower(), 0) for f in findings)
    score = min(raw, 100)
    label = (
        "Critical" if score >= 80 else
        "High"     if score >= 60 else
        "Medium"   if score >= 30 else
        "Low"      if score >= 10 else
        "Informational"
    )
    return score, label


def generate_markdown(
    target: str,
    findings: list[dict],
    breach_data: Optional[dict]  = None,
    alive_count: int             = 0,
    subdomain_count: int         = 0,
    scan_notes: dict             = None,
) -> str:
    ts       = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    sorted_f = sorted(findings, key=_sev)
    scan_notes = scan_notes or {}

    counts = {s: sum(1 for f in findings if (f.get("severity") or "info").lower() == s)
              for s in SEV_ORDER}
    risk_score, risk_label = _risk_score(findings)

    lines = [
        "# EVHunter Security Assessment Report",
        "",
        f"> **Target:** `{target}`  ",
        f"> **Date:** {ts}  ",
        f"> **Tool:** EVHunter v2.0 — AI-Augmented Bug Hunter Framework  ",
        f"> **Overall Risk:** **{risk_label}** ({risk_score}/100)",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Subdomains Discovered | {subdomain_count} |",
        f"| Live Hosts            | {alive_count} |",
        f"| Total Findings        | {len(findings)} |",
        f"| 🔴 Critical           | {counts['critical']} |",
        f"| 🟠 High               | {counts['high']} |",
        f"| 🟡 Medium             | {counts['medium']} |",
        f"| 🔵 Low                | {counts['low']} |",
        f"| ⚪ Info               | {counts['info']} |",
        f"| Overall Risk Score    | **{risk_score}/100 — {risk_label}** |",
        "",
        "---",
        "",
    ]

    # ── WAF / Tech ────────────────────────────────────────────────────────────
    if "waf" in scan_notes:
        waf_data = scan_notes["waf"]
        detected = waf_data.get("detected", [])
        if detected:
            lines += [
                "## Infrastructure",
                "",
                "**Detected WAF/CDN Components:**",
                "",
            ]
            for d in detected:
                lines.append(f"- **{d['name']}** ({d['type']})")
            lines += ["", "---", ""]

    if "tech" in scan_notes:
        tech_data = scan_notes["tech"]
        tech_list = tech_data.get("tech", [])
        if tech_list:
            lines += ["## Technology Stack", "", "|Technology|Category|Confidence|", "|---|---|---|"]
            for t in tech_list:
                lines.append(f"|{t['name']}|{t['category']}|{t['confidence']}%|")
            lines += ["", "---", ""]

    # ── DNS ───────────────────────────────────────────────────────────────────
    if "dns" in scan_notes:
        dns = scan_notes["dns"]
        lines += ["## DNS Analysis", ""]
        sec = dns.get("security", {})
        lines += [
            f"| Check | Result |",
            f"|-------|--------|",
            f"| SPF Record   | {'✅ Present' if sec.get('spf')   else '❌ Missing'} |",
            f"| DMARC Policy | {'✅ Present' if sec.get('dmarc') else '❌ Missing'} |",
            f"| DKIM Record  | {'✅ Present' if sec.get('dkim')  else '❌ Missing'} |",
            "",
        ]
        if dns.get("zone_transfer"):
            lines += [
                "⚠️ **Zone transfer exposed on this domain!**",
                "",
                "```",
                "\n".join(dns["zone_transfer"][:10]),
                "```",
                "",
            ]
        lines += ["---", ""]

    # ── SSL ───────────────────────────────────────────────────────────────────
    if "ssl" in scan_notes:
        ssl = scan_notes["ssl"]
        cert = ssl.get("cert", {})
        lines += [
            "## SSL/TLS Analysis",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Grade   | **{ssl.get('grade', 'N/A')}** |",
            f"| Subject | `{cert.get('subject', 'N/A')}` |",
            f"| Issuer  | {cert.get('issuer', 'N/A')} |",
            f"| Expires | {cert.get('expiry', 'N/A')} ({cert.get('days_left', '?')} days) |",
            f"| Cipher  | `{ssl.get('cipher', {}).get('name', 'N/A')}` |",
            "",
        ]
        for issue in ssl.get("issues", []):
            sev = issue["severity"]
            lines.append(f"- {SEV_EMOJI.get(sev, '⚪')} **{issue['type']}**: {issue['detail']}")
        lines += ["", "---", ""]

    # ── CORS ──────────────────────────────────────────────────────────────────
    if "cors" in scan_notes and scan_notes["cors"].get("findings"):
        cors = scan_notes["cors"]
        lines += ["## CORS Misconfigurations", ""]
        for f in cors["findings"]:
            sev = f["severity"]
            lines += [
                f"### {SEV_EMOJI.get(sev,'⚪')} CORS — {f['label']}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| URL | `{f['url']}` |",
                f"| Test Origin | `{f['origin']}` |",
                f"| ACAO Header | `{f['acao']}` |",
                f"| Allow-Credentials | `{f.get('acac', 'false')}` |",
                f"| Severity | `{sev.upper()}` |",
                "",
                f"> {f['detail']}",
                "",
            ]
        lines += ["---", ""]

    # ── Secrets ───────────────────────────────────────────────────────────────
    if "secrets" in scan_notes and scan_notes["secrets"].get("secrets"):
        secrets = scan_notes["secrets"]["secrets"]
        lines += [
            "## Exposed Secrets / Credentials",
            "",
            f"⚠️ **{len(secrets)} secret(s) found in HTTP responses!**",
            "",
            "| Type | Match (truncated) | Severity | URL |",
            "|------|-------------------|----------|-----|",
        ]
        for s in secrets[:20]:
            match_safe = s["match"][:25].replace("|", "\\|")
            lines.append(f"|{s['type']}|`{match_safe}…`|{s['severity'].upper()}|{s['url'][:40]}|")
        lines += ["", "---", ""]

    # ── JS Analysis ───────────────────────────────────────────────────────────
    if "js" in scan_notes:
        js = scan_notes["js"]
        if js.get("endpoints") or js.get("s3_buckets") or js.get("secrets"):
            lines += ["## JavaScript Analysis", ""]
            if js.get("js_files"):
                lines.append(f"**{len(js['js_files'])} JS files analyzed**")
            if js.get("endpoints"):
                lines += ["", "**API Endpoints Discovered:**", ""]
                for ep in js["endpoints"][:20]:
                    lines.append(f"- `{ep}`")
            if js.get("s3_buckets"):
                lines += ["", "**⚠️ S3 Buckets Referenced:**", ""]
                for b in js["s3_buckets"]:
                    lines.append(f"- `{b}`")
            if js.get("sourcemaps"):
                lines += ["", f"**⚠️ {len(js['sourcemaps'])} Source Map(s) found** — may expose original source code", ""]
            lines += ["", "---", ""]

    # ── Breach ────────────────────────────────────────────────────────────────
    if breach_data:
        lines += [
            "## Breach Intelligence",
            "",
            "```json",
            json.dumps(breach_data, indent=2)[:1000],
            "```",
            "",
            "---",
            "",
        ]

    # ── Vulnerability Findings ────────────────────────────────────────────────
    lines += ["## Vulnerability Findings", ""]

    if not sorted_f:
        lines += ["*No vulnerabilities recorded.*", ""]
    else:
        for i, f in enumerate(sorted_f, 1):
            sev   = (f.get("severity") or "info").lower()
            emoji = SEV_EMOJI.get(sev, "⚪")
            rep: dict = {}
            if f.get("report"):
                try:
                    rep = json.loads(f["report"]) if isinstance(f["report"], str) else (f["report"] or {})
                except Exception:
                    rep = {}

            lines += [
                f"### {i}. {emoji} {f.get('title', 'Unnamed Finding')}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Severity**     | `{sev.upper()}` |",
                f"| **Asset**        | `{f.get('asset', '?')}` |",
                f"| **Module**       | {f.get('module', 'ai')} |",
                f"| **Confirmed**    | {'✅ Yes' if f.get('confirmed') else '⏳ Pending verification'} |",
                f"| **CVSS Range**   | {rep.get('cvss_estimate', SEV_CVSS.get(sev, 'N/A'))} |",
                "",
            ]

            detail = rep.get("description") or f.get("detail", "")
            if detail:
                lines += ["**Description**", "", detail, ""]

            if rep.get("impact"):
                lines += ["**Impact**", "", rep["impact"], ""]

            if rep.get("steps_to_reproduce"):
                lines += ["**Steps to Reproduce**", "", rep["steps_to_reproduce"], ""]

            poc = f.get("curl_poc") or rep.get("curl_poc", "")
            if poc:
                lines += ["**Proof of Concept**", "", "```bash", poc, "```", ""]

            remediation = rep.get("remediation") or ""
            if remediation:
                lines += ["**Remediation**", "", f"> {remediation}", ""]

            if rep.get("references"):
                lines += ["**References**", ""]
                for ref in rep["references"][:5]:
                    lines.append(f"- {ref}")
                lines.append("")

            lines += ["---", ""]

    lines += [
        "## Disclaimer",
        "",
        "This report was generated by EVHunter for authorized security testing purposes only.",
        "All findings should be verified manually before disclosure.",
        "The tool operators are not responsible for misuse of this information.",
        "",
    ]

    return "\n".join(lines)


def generate_html(markdown_content: str, target: str) -> str:
    """Convert markdown to professional HTML report."""
    try:
        import markdown as md_lib
        html_body = md_lib.markdown(
            markdown_content,
            extensions=["tables", "fenced_code", "toc", "attr_list"]
        )
    except ImportError:
        # Fallback: basic conversion
        html_body = _basic_md_to_html(markdown_content)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EVHunter Report — {target}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg:        #0d1117;
    --surface:   #161b22;
    --border:    #30363d;
    --text:      #c9d1d9;
    --text-dim:  #8b949e;
    --blue:      #58a6ff;
    --blue-lt:   #79c0ff;
    --orange:    #ffa657;
    --green:     #3fb950;
    --red:       #f85149;
    --yellow:    #d29922;
  }}
  body    {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.65; padding: 2rem 1rem; }}
  .wrap   {{ max-width: 960px; margin: 0 auto; }}
  .header {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; margin-bottom: 2rem; border-left: 4px solid var(--blue); }}
  .header h1 {{ font-size: 1.8rem; color: var(--blue); margin-bottom: .5rem; }}
  .header p  {{ color: var(--text-dim); font-size: .9rem; }}
  h1      {{ font-size: 1.6rem; color: var(--blue);    border-bottom: 2px solid var(--border); padding-bottom: .4rem; margin: 2rem 0 1rem; }}
  h2      {{ font-size: 1.25rem; color: var(--blue-lt); margin: 1.8rem 0 .8rem; border-left: 3px solid #388bfd; padding-left: .7rem; }}
  h3      {{ font-size: 1.05rem; color: var(--orange);  margin: 1.4rem 0 .6rem; }}
  h4      {{ font-size: .95rem; color: var(--text);    margin: 1rem 0 .4rem; }}
  p       {{ margin: .5rem 0; }}
  a       {{ color: var(--blue); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  table   {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: .88rem; }}
  th      {{ background: var(--surface); color: var(--blue); padding: .5rem .8rem; border: 1px solid var(--border); text-align: left; }}
  td      {{ padding: .45rem .8rem; border: 1px solid var(--border); }}
  tr:nth-child(even) {{ background: #0f1318; }}
  code    {{ background: var(--surface); padding: .1rem .35rem; border-radius: 4px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: .82rem; color: #e6edf3; border: 1px solid var(--border); }}
  pre     {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.1rem; overflow-x: auto; margin: .8rem 0; }}
  pre code{{ background: none; padding: 0; border: none; font-size: .83rem; }}
  blockquote {{ border-left: 3px solid var(--green); padding: .4rem 1rem; color: var(--text-dim); margin: .8rem 0; background: #0f1f13; border-radius: 0 6px 6px 0; }}
  hr      {{ border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }}
  strong  {{ color: #e6edf3; }}
  ul, ol  {{ margin: .5rem 0 .5rem 1.5rem; }}
  li      {{ margin: .2rem 0; }}
  .toc    {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.5rem; margin: 1.5rem 0; }}
  .toc h2 {{ border: none; font-size: 1rem; margin: 0 0 .6rem; padding: 0; }}
  .risk-badge {{ display: inline-block; background: var(--red); color: #fff; border-radius: 6px; padding: .2rem .6rem; font-size: .8rem; font-weight: bold; }}
  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: .8rem; text-align: center; }}
</style>
</head>
<body>
<div class="wrap">
<div class="header">
  <h1>🔍 EVHunter Security Assessment</h1>
  <p><strong>Target:</strong> {target} &nbsp;|&nbsp; <strong>Generated:</strong> {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} &nbsp;|&nbsp; EVHunter v2.0</p>
</div>
{html_body}
<div class="footer">Generated by EVHunter v2.0 — AI-Augmented Bug Hunter Framework &nbsp;|&nbsp; For authorized testing only</div>
</div>
</body>
</html>"""


def _basic_md_to_html(md: str) -> str:
    """Minimal MD→HTML fallback (no external deps)."""
    import re
    h = md
    for pat, repl in [
        (r"^#### (.+)$", r"<h4>\1</h4>"),
        (r"^### (.+)$",  r"<h3>\1</h3>"),
        (r"^## (.+)$",   r"<h2>\1</h2>"),
        (r"^# (.+)$",    r"<h1>\1</h1>"),
        (r"\*\*(.+?)\*\*", r"<strong>\1</strong>"),
        (r"\*(.+?)\*",     r"<em>\1</em>"),
        (r"`(.+?)`",       r"<code>\1</code>"),
        (r"^> (.+)$",      r"<blockquote>\1</blockquote>"),
        (r"^---$",         r"<hr>"),
    ]:
        h = re.sub(pat, repl, h, flags=re.MULTILINE)
    h = re.sub(r"```(\w+)?\n(.*?)```", r"<pre><code>\2</code></pre>", h, flags=re.DOTALL)
    return h


def save_report(
    target: str,
    findings: list[dict],
    reports_dir: Path,
    breach_data: Optional[dict] = None,
    alive_count: int            = 0,
    subdomain_count: int        = 0,
    scan_notes: dict            = None,
) -> tuple[Path, Path, Path]:
    """Generate and save Markdown, HTML, and JSON reports."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)
    ts   = time.strftime("%Y%m%d_%H%M%S")

    md_path   = reports_dir / f"{slug}_{ts}.md"
    html_path = reports_dir / f"{slug}_{ts}.html"
    json_path = reports_dir / f"{slug}_{ts}.json"

    md_content = generate_markdown(
        target, findings, breach_data, alive_count, subdomain_count, scan_notes
    )
    md_path.write_text(md_content, encoding="utf-8")
    html_path.write_text(generate_html(md_content, target), encoding="utf-8")

    # JSON export
    json_path.write_text(json.dumps({
        "target":    target,
        "generated": ts,
        "findings":  findings,
        "notes":     scan_notes or {},
    }, indent=2, default=str), encoding="utf-8")

    console.print(Panel(
        f"[bold green]  Reports saved:[/bold green]\n\n"
        f"  [cyan]Markdown:[/cyan] {md_path}\n"
        f"  [cyan]HTML:[/cyan]     {html_path}\n"
        f"  [cyan]JSON:[/cyan]     {json_path}",
        border_style="green",
        title="[bold]📄 Report Generated[/bold]",
    ))

    return md_path, html_path, json_path
