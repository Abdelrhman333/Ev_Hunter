# EVHunter — AI-Augmented Bug Hunter Framework
> Low-Token Edition | v1.0

An organized, AI-powered CLI bug hunting framework that combines industry-standard
recon tools with AI analysis to identify and verify vulnerabilities.

---

## Features

| Module | What it does |
|--------|-------------|
| **Nmap** | Port scan with service/version detection |
| **AI Recon Analyst** | Identifies attack surface from scan data |
| **Subdomain Enum** | subfinder + crt.sh certificate transparency |
| **HTTP Probe** | Concurrent alive host detection |
| **AI Subdomain Analyst** | Flags sensitive subdomains (staging, admin, etc.) |
| **Nuclei** | Low-hanging fruit scanner (critical/high/medium) |
| **AI Vuln Analyst** | Analyzes tech stack + endpoints for vulnerabilities |
| **Curl Verifier** | Executes AI-generated PoC commands |
| **AI Verifier** | Confirms findings from curl responses |
| **Breach Check** | OSINTCat API for breach intelligence |
| **Report Writer** | AI-generated professional vuln reports |
| **DB Storage** | SQLite for findings persistence |

## Token Optimization

Instead of sending raw HTML/output to the AI, BugHunter sends **compact JSON payloads**:

```json
{
  "url": "https://api.target.com",
  "status": 403,
  "tech": ["nginx", "graphql"],
  "headers": {"server": "nginx"},
  "interesting_patterns": ["graphql endpoint", "debug header"]
}
```

Results in ~80-90% token reduction vs. sending raw outputs.

---

## Installation

```bash
git clone <repo>
cd bughunter
chmod +x install.sh && ./install.sh
```

## Setup

```bash
python3 main.py configure
```

You'll be prompted for:
- AI provider URL (any OpenAI-compatible API)
- AI API key
- Model name (e.g. `gpt-4o-mini`, `claude-sonnet-4-6`, etc.)
- OSINTCat API key (for breach data)
- Rate limit & concurrency settings

---

## Usage

### Recon (full pipeline)
```bash
python3 main.py recon example.com
python3 main.py recon example.com --deep          # Top-1000 ports
python3 main.py recon example.com --no-nuclei     # Skip nuclei
python3 main.py recon example.com --no-verify     # Skip curl verification
python3 main.py recon example.com --no-report     # Skip report generation
```

### History
```bash
python3 main.py history
```

### Regenerate Report
```bash
python3 main.py report 3   # Scan ID from history
```

### Re-configure
```bash
python3 main.py configure
```

---

## External Tools Required

| Tool | Install |
|------|---------|
| `nmap` | `sudo apt install nmap` |
| `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `curl` | Pre-installed on most systems |

BugHunter works without them (with reduced functionality).

---

## Output

Reports are saved to `~/.bughunter/reports/` in both **Markdown** and **HTML** format.

---

## AI Providers

Any OpenAI-compatible API works:

| Provider | API URL | Recommended Model |
|----------|---------|------------------|
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Anthropic (via proxy) | your proxy URL | `claude-haiku-*` |
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| Ollama (local) | `http://localhost:11434/v1` | `llama3.2` |
| Together | `https://api.together.xyz/v1` | `meta-llama/...` |

---

## Legal Notice

> **This tool is for authorized security testing only.**
> Unauthorized use may violate computer fraud and abuse laws.
> You are solely responsible for your actions.

---

## Architecture

```
bughunter/
├── main.py           ← CLI entry point (typer + rich)
├── config.py         ← Config wizard + persistence
├── ai_client.py      ← AI client (4 agents, low-token)
├── db.py             ← SQLite storage
├── modules/
│   ├── recon.py      ← nmap, subfinder, crt.sh, httpx, nuclei, breach
│   └── reporting.py  ← Markdown + HTML report generation
├── requirements.txt
└── install.sh
```
