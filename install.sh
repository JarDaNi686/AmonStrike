#!/bin/bash
# AmonStrike v3.0 — Complete Kali Linux Installer
# Run as: sudo bash amonstrike_install.sh

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[~]${NC} $1"; }
err()  { echo -e "${RED}[!]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

echo -e "${BOLD}${RED}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║     AmonStrike v3.0 — Kali Installer      ║"
echo "  ║    Hidden Recon. Precise Strike. Proof.   ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Clone repository ───────────────────────────────────────

log "Step 1/7: Cloning AmonStrike..."

# Need sudo to write to /opt
if [ "$EUID" -ne 0 ]; then
    err "Please run as root: sudo bash amonstrike_install.sh"
    exit 1
fi

cd /opt
if [ -d "AmonStrike" ]; then
    warn "AmonStrike already exists — pulling latest..."
    cd AmonStrike && git pull origin main
else
    git clone https://github.com/JarDaNi686/AmonStrike.git
    cd AmonStrike
fi

log "Repository ready at /opt/AmonStrike"

# ── 2. Python dependencies (Kali-compatible) ──────────────────

log "Step 2/7: Installing Python dependencies (Kali method)..."

# Kali uses --break-system-packages for pip
# This is safe — Kali is a dedicated security platform
pip3 install --break-system-packages \
    requests beautifulsoup4 flask pillow pyyaml \
    aiohttp aiofiles dnspython tldextract \
    websockets lxml 2>/dev/null && log "Python packages installed" \
    || warn "Some pip packages failed — trying pipx fallback..."

# Also try apt for packages that have apt equivalents
apt-get install -y -q \
    python3-requests python3-bs4 python3-flask \
    python3-pil python3-yaml python3-lxml \
    2>/dev/null && log "apt Python packages installed" \
    || warn "Some apt packages unavailable"

# ── 3. Playwright (headless browser for screenshots) ──────────

log "Step 3/7: Installing Playwright for screenshots..."

# First try pip with --break-system-packages
pip3 install --break-system-packages playwright 2>/dev/null \
    && python3 -m playwright install chromium 2>/dev/null \
    && log "Playwright + Chromium installed" \
    || {
        warn "pip playwright failed — trying pipx..."
        apt-get install -y -q pipx 2>/dev/null || true
        pipx install playwright 2>/dev/null \
            && python3 -m playwright install chromium 2>/dev/null \
            && log "Playwright via pipx installed" \
            || warn "Playwright unavailable — screenshots will use placeholders"
    }

# ── 4. System tools (apt) ─────────────────────────────────────

log "Step 4/7: Installing system security tools..."

apt-get update -q 2>/dev/null | tail -1

tools_apt="nmap sqlmap ffuf gobuster curl wget git"
for tool in $tools_apt; do
    if command -v $tool &>/dev/null; then
        echo "    ✓ $tool already installed"
    else
        apt-get install -y -q $tool 2>/dev/null \
            && echo "    ✓ $tool installed" \
            || echo "    ~ $tool unavailable"
    fi
done

# ── 5. Go + ProjectDiscovery tools ───────────────────────────

log "Step 5/7: Installing Go + ProjectDiscovery tools..."

# Install Go
if ! command -v go &>/dev/null; then
    apt-get install -y -q golang 2>/dev/null \
        && log "Go installed via apt" \
        || {
            warn "apt Go failed — downloading from golang.org..."
            wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz \
                -O /tmp/go.tar.gz
            tar -C /usr/local -xzf /tmp/go.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
            export PATH=$PATH:/usr/local/go/bin
        }
fi

export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
echo "    Go version: $(go version)"

# Install ProjectDiscovery tools
PD_TOOLS="
github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
github.com/projectdiscovery/dnsx/cmd/dnsx@latest
github.com/projectdiscovery/httpx/cmd/httpx@latest
github.com/projectdiscovery/katana/cmd/katana@latest
github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
github.com/tomnomnom/anew@latest
github.com/tomnomnom/waybackurls@latest
github.com/tomnomnom/assetfinder@latest
github.com/tomnomnom/qsreplace@latest
github.com/lc/gau/v2/cmd/gau@latest
github.com/PentestPad/subzy@latest
"

for pkg in $PD_TOOLS; do
    tool=$(basename $pkg | cut -d@ -f1)
    if command -v $tool &>/dev/null || [ -f "$GOPATH/bin/$tool" ]; then
        echo "    ✓ $tool already installed"
    else
        GOPATH=/root/go go install $pkg 2>/dev/null \
            && echo "    ✓ $tool installed" \
            || echo "    ~ $tool failed (needs internet)"
    fi
done

# Update PATH permanently
if ! grep -q "GOPATH" /root/.bashrc; then
    echo 'export GOPATH=/root/go' >> /root/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> /root/.bashrc
fi

# ── 6. Create wrapper scripts ─────────────────────────────────

log "Step 6/7: Creating wrapper scripts..."

# Main launcher
cat > /usr/local/bin/amonstrike << 'WRAPPER'
#!/bin/bash
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin
cd /opt/AmonStrike
python3 amonstrike.py "$@"
WRAPPER
chmod +x /usr/local/bin/amonstrike

# Recon pipeline wrapper
cat > /usr/local/bin/amonstrike-recon << 'WRAPPER'
#!/bin/bash
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin
cd /opt/AmonStrike
python3 recon/pipeline.py "$@"
WRAPPER
chmod +x /usr/local/bin/amonstrike-recon

# Monitor wrapper
cat > /usr/local/bin/amonstrike-monitor << 'WRAPPER'
#!/bin/bash
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin
cd /opt/AmonStrike
python3 recon/monitor.py "$@"
WRAPPER
chmod +x /usr/local/bin/amonstrike-monitor

# Dashboard wrapper
cat > /usr/local/bin/amonstrike-dashboard << 'WRAPPER'
#!/bin/bash
cd /opt/AmonStrike
python3 dashboard/app.py &
sleep 2
firefox http://localhost:5000 2>/dev/null &
echo "[+] Dashboard running at http://localhost:5000"
WRAPPER
chmod +x /usr/local/bin/amonstrike-dashboard

log "Wrappers created: amonstrike, amonstrike-recon, amonstrike-monitor, amonstrike-dashboard"

# ── 7. Nuclei templates ───────────────────────────────────────

log "Step 7/7: Downloading Nuclei templates..."

if command -v nuclei &>/dev/null || [ -f "$GOPATH/bin/nuclei" ]; then
    NUCLEI_BIN="${GOPATH}/bin/nuclei"
    [ -f "$NUCLEI_BIN" ] || NUCLEI_BIN=$(which nuclei)
    $NUCLEI_BIN -update-templates -silent 2>/dev/null \
        && log "Nuclei templates updated" \
        || warn "Nuclei template update failed (needs internet)"
else
    warn "Nuclei not installed — templates will download on first run"
fi

# ── Done ──────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║  AmonStrike v3.0 installed successfully!              ║"
echo "  ╠═══════════════════════════════════════════════════════╣"
echo "  ║                                                       ║"
echo "  ║  QUICK START:                                         ║"
echo "  ║                                                       ║"
echo "  ║  # Practice target (always legal):                   ║"
echo "  ║  amonstrike --url http://testphp.vulnweb.com          ║"
echo "  ║                                                       ║"
echo "  ║  # Full recon pipeline:                              ║"
echo "  ║  amonstrike-recon testphp.vulnweb.com ./output       ║"
echo "  ║                                                       ║"
echo "  ║  # 24/7 monitor:                                     ║"
echo "  ║  amonstrike-monitor TARGET.com                       ║"
echo "  ║                                                       ║"
echo "  ║  # Web dashboard:                                    ║"
echo "  ║  amonstrike-dashboard                                 ║"
echo "  ║                                                       ║"
echo "  ║  Repo: github.com/JarDaNi686/AmonStrike              ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Quick verify
echo -e "${CYAN}[i] Verifying installation...${NC}"
cd /opt/AmonStrike
python3 -c "
import sys; sys.path.insert(0,'.')
try:
    from recon.pipeline   import ReconPipeline
    from recon.auth_engine import SessionManager
    from recon.monitor    import ReconMonitor
    from verify.screenshot import ScreenshotEngine
    print('  ✓ All core modules import successfully')
except Exception as e:
    print(f'  ~ Import warning: {e}')
"

echo ""
log "Installation complete! Run: amonstrike --url http://testphp.vulnweb.com"
