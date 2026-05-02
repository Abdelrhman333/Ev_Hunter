#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  BugHunter — Install Script
#  Usage: chmod +x install.sh && ./install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

info()  { echo -e "${CYAN}  ▸ $*${NC}"; }
ok()    { echo -e "${GREEN}  ✔ $*${NC}"; }
warn()  { echo -e "${YELLOW}  ⚠ $*${NC}"; }
error() { echo -e "${RED}  ✖ $*${NC}"; exit 1; }

echo ""
echo -e "${BOLD}${CYAN}  BugHunter — Installation${NC}"
echo -e "  ${BOLD}AI-Augmented Bug Hunter Framework${NC}"
echo ""

# ── Python ────────────────────────────────────────────────────────────────────
info "Checking Python 3.10+…"
python3 --version >/dev/null 2>&1 || error "Python 3 not found. Install it first."
PY_VER=$(python3 -c 'import sys; print(sys.version_info.minor)')
[ "$PY_VER" -ge 10 ] || error "Python 3.10+ required (found 3.$PY_VER)"
ok "Python OK"

# ── pip packages ─────────────────────────────────────────────────────────────
info "Installing Python dependencies…"
pip install -q -r requirements.txt || pip3 install -q -r requirements.txt
ok "Python deps installed"

# ── Optional external tools ───────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Optional External Tools${NC} (install for full functionality)"

check_tool() {
    if command -v "$1" &>/dev/null; then
        ok "$1 found"
    else
        warn "$1 not found — $2"
    fi
}

check_tool nmap       "install: sudo apt install nmap  /  brew install nmap"
check_tool subfinder  "install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_tool httpx      "install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_tool nuclei     "install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
check_tool curl       "install: sudo apt install curl  /  brew install curl"

# ── Alias ─────────────────────────────────────────────────────────────────────
TOOL_DIR=$(pwd)
ALIAS_LINE="alias bughunter='python3 ${TOOL_DIR}/main.py'"

echo ""
info "Adding shell alias…"

if [ -f "$HOME/.bashrc" ]; then
    grep -q "alias bughunter=" "$HOME/.bashrc" || echo "$ALIAS_LINE" >> "$HOME/.bashrc"
    ok "Added to ~/.bashrc"
fi
if [ -f "$HOME/.zshrc" ]; then
    grep -q "alias bughunter=" "$HOME/.zshrc" || echo "$ALIAS_LINE" >> "$HOME/.zshrc"
    ok "Added to ~/.zshrc"
fi

echo ""
echo -e "${GREEN}${BOLD}  ✔ Installation complete!${NC}"
echo ""
echo -e "  Run setup:"
echo -e "  ${CYAN}  source ~/.bashrc && bughunter configure${NC}"
echo -e "  or"
echo -e "  ${CYAN}  python3 main.py configure${NC}"
echo ""
