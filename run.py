import os
#!/usr/bin/env python3
"""
AmonStrike — One URL in. Everything out.
Usage: sudo python3 run.py <H1_program_URL>
"""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

if len(sys.argv) < 2:
    print("Usage: sudo python3 run.py https://target.com [program_handle]")
    print("Example: sudo python3 run.py https://www.army.mil dod")
    sys.exit(1)

url    = sys.argv[1]
handle = sys.argv[2] if len(sys.argv) > 2 else ""

from core.master_engine import MasterEngine
from core.burp_integration import BurpIntegration

# Check for Burp
burp = BurpIntegration()
if "--burp" in sys.argv and not burp.available:
    BurpIntegration.launch_burp()
    burp = BurpIntegration()

if burp.available:
    print("[BURP] All traffic routed through Burp Suite")
    os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"
    os.environ["HTTP_PROXY"]  = "http://127.0.0.1:8080"

engine = MasterEngine(url, handle)
engine.run()

# Collect Burp findings too
if burp.available:
    burp_findings = burp.get_findings_from_burp()
    if burp_findings:
        print(f"[BURP] {len(burp_findings)} additional findings from Burp Scanner")
