#!/bin/bash
# AmonStrike — Full Autonomous Pentest
# One command. Everything runs. No human needed.
#
# Usage: sudo bash amonstrike.sh https://claude.ai anthropic

TARGET=${1:-"https://claude.ai"}
PROGRAM=${2:-"anthropic"}

echo "
╔══════════════════════════════════════════════════════════╗
║  AMONSTRIKE — FULL AUTONOMOUS PENTEST                    ║
║  Target:  $TARGET
║  Program: $PROGRAM
╚══════════════════════════════════════════════════════════╝
"

cd /opt/AmonStrike

# Step 1: Pull latest
echo "[1/7] Updating..."
git pull -q

# Step 2: Verify pipeline
echo "[2/7] Verifying pipeline..."
python3 test_pipeline.py 2>/dev/null | tail -3

# Step 3: Install missing tools
echo "[3/7] Checking tools..."
for tool in sqlmap nikto gobuster nmap nuclei subfinder httpx dalfox; do
    if ! command -v $tool &>/dev/null; then
        echo "  Installing $tool..."
        apt-get install -y $tool -qq 2>/dev/null || \
        go install github.com/projectdiscovery/${tool}/v2/cmd/${tool}@latest 2>/dev/null
    fi
done

# Step 4: Start Ollama if not running
echo "[4/7] Starting AI brain..."
if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
    ollama serve &>/dev/null &
    sleep 3
fi

# Step 5: Start Burp if installed
echo "[5/7] Starting Burp Suite..."
if command -v burpsuite &>/dev/null; then
    burpsuite --headless.mode=true &>/dev/null &
    sleep 5
fi

# Step 6: Run full professional scan
echo "[6/7] Running full pentest..."
python3 run.py "$TARGET" "$PROGRAM"

# Step 7: Run cross-account IDOR test
echo "[7/7] Running automated IDOR tests..."
python3 core/api_interceptor.py

echo "
╔══════════════════════════════════════════════════════════╗
║  COMPLETE. Check output/ directory for findings.         ║
╚══════════════════════════════════════════════════════════╝
"
