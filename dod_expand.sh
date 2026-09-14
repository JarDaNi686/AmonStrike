#!/bin/bash
# Expand DoD scan to all discovered subdomains
echo "[*] Fetching army.mil subdomains from crt.sh..."
curl -s "https://crt.sh/?q=%.army.mil&output=json" | \
  python3 -c "
import json,sys
data = json.load(sys.stdin)
seen = set()
for e in data:
    for name in e.get('name_value','').split('\n'):
        name = name.strip().lstrip('*.')
        if name.endswith('.mil') and name not in seen:
            seen.add(name)
            print(f'https://{name}')
" | head -50 > /tmp/dod_targets.txt

echo "[+] $(wc -l < /tmp/dod_targets.txt) targets found"
echo "[*] Checking which are alive..."

if command -v httpx &>/dev/null; then
  httpx -silent -timeout 10 -rate-limit 20 \
    -l /tmp/dod_targets.txt > /tmp/dod_alive.txt
  echo "[+] $(wc -l < /tmp/dod_alive.txt) alive targets"
else
  cp /tmp/dod_targets.txt /tmp/dod_alive.txt
fi

echo "[*] Scanning top targets with AmonStrike..."
head -10 /tmp/dod_alive.txt | while read target; do
  echo ""
  echo "=== $target ==="
  sudo python3 run.py "$target" dod
  sleep 5
done
