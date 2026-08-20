# AmonStrike v3.0 — Installation Guide

## Kali Linux (Recommended)

```bash
# 1. Clone
sudo git clone https://github.com/JarDaNi686/AmonStrike.git /opt/AmonStrike
cd /opt/AmonStrike

# 2. Python packages (Kali requires --break-system-packages)
sudo pip3 install --break-system-packages -r requirements.txt

# 3. Playwright browser (for screenshots)
sudo python3 -m playwright install chromium

# 4. Go + ProjectDiscovery tools
sudo apt install golang -y
export GOPATH=/root/go && export PATH=$PATH:$GOPATH/bin

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/assetfinder@latest

# 5. Nuclei templates
nuclei -update-templates

# 6. Run (ALWAYS from /opt/AmonStrike directory)
cd /opt/AmonStrike
sudo python3 amonstrike.py --url http://testphp.vulnweb.com --mode normal
```

## One-Line Auto-Installer

```bash
sudo bash <(curl -s https://raw.githubusercontent.com/JarDaNi686/AmonStrike/main/install.sh)
```

## Quick Commands

```bash
# Scan a target
cd /opt/AmonStrike
sudo python3 amonstrike.py --url http://testphp.vulnweb.com --mode normal

# Recon pipeline
sudo python3 recon/pipeline.py testphp.vulnweb.com ./output/recon/

# IDOR scan
sudo python3 -c "
import sys; sys.path.insert(0,'.')
from recon.auth_engine import SessionManager, IDORScanner
sm = SessionManager('http://TARGET.com')
sm.add_user('user1@email.com', 'password1', 'user')
sm.add_user('user2@email.com', 'password2', 'user')
sm.login_all()
findings = IDORScanner('http://TARGET.com', sm).scan()
print(f'{len(findings)} findings')
"

# Custom Nuclei templates
sudo python3 -c "
import sys; sys.path.insert(0,'.')
from recon.nuclei_engine import NucleiTemplateEngine
eng = NucleiTemplateEngine()
templates = eng.generate_all_templates('http://TARGET.com')
findings  = eng.run_templates('http://TARGET.com', templates)
print(f'{len(findings)} findings')
"

# 24/7 Monitor
sudo python3 recon/monitor.py TARGET.com TARGET2.com

# Web dashboard
python3 dashboard/app.py
# Open: http://localhost:5000
```

## CRITICAL: Always run from /opt/AmonStrike directory

Every Python command must be run from /opt/AmonStrike so module imports work:

```bash
cd /opt/AmonStrike   # ← This is mandatory
python3 amonstrike.py ...
```

## Troubleshooting

| Error | Fix |
|-------|-----|
| `Permission denied` cloning to `/opt` | Use `sudo git clone` |
| `externally-managed-environment` | Add `--break-system-packages` to pip |
| `ModuleNotFoundError: recon` | Run from `/opt/AmonStrike` directory |
| `playwright not found` | `sudo python3 -m playwright install chromium` |
| `go: command not found` | `sudo apt install golang` |
| `subfinder not found` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
